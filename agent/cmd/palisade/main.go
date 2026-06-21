// Command palisade is the Palisade agent: a thin, pull-only agent that enrolls
// once, then heartbeats the control plane, discovers local services, and runs
// detections on-host. It never accepts inbound connections.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"palisade/agent/internal/catalog"
	"palisade/agent/internal/client"
	"palisade/agent/internal/config"
	"palisade/agent/internal/discover"
	"palisade/agent/internal/scan"
)

// version is the reported agent version.
const version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("palisade: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `palisade — attack-surface monitoring agent

Usage:
  palisade enroll --token <t> --server <url>   Enroll this host (writes config)
  palisade run [--server <url>]                Run the heartbeat/scan loop

Config is stored in $PALISADE_HOME/config.json (default ./.palisade).
`)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "one-time enrollment token (required)")
	server := fs.String("server", "", "control plane base URL (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *server == "" {
		return fmt.Errorf("both --token and --server are required")
	}

	hostname, _ := os.Hostname()
	c := client.New(*server, "")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.Enroll(ctx, catalog.EnrollRequest{
		EnrollToken: *token,
		Host: catalog.HostInfo{
			Hostname:     hostname,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			AgentVersion: version,
		},
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	if err := config.Save(&config.Config{
		AgentID:       resp.AgentID,
		AgentSecret:   resp.AgentSecret,
		Server:        *server,
		ClientCertPEM: resp.ClientCertPEM,
		ClientKeyPEM:  resp.ClientKeyPEM,
		CACertPEM:     resp.CACertPEM,
	}); err != nil {
		return err
	}

	log.Printf("enrolled as agent %s (heartbeat every %ds)", resp.AgentID, resp.HeartbeatIntervalS)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	server := fs.String("server", "", "override control plane base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *server != "" {
		cfg.Server = *server
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c, err := client.NewWithCerts(cfg.Server, cfg.AgentSecret, cfg.ClientCertPEM, cfg.ClientKeyPEM, cfg.CACertPEM)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	a := &agent{
		cfg:     cfg,
		client:  c,
		scanner: scan.New(),
		// assetIDs is populated by discover jobs: "<host>:<port>" -> asset id.
		assetIDs: map[string]string{},
	}

	// heartbeat_interval_s default per contract; refreshed from enroll if we
	// later persist it. Start at 30s. PALISADE_HEARTBEAT_INTERVAL_S overrides it
	// (operators tuning cadence; integration tests collapsing the loop).
	interval := 30 * time.Second
	if v := os.Getenv("PALISADE_HEARTBEAT_INTERVAL_S"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	log.Printf("running: server=%s agent=%s interval=%s", cfg.Server, cfg.AgentID, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	a.tick(ctx) // run immediately, don't wait a full interval
	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down")
			return nil
		case <-ticker.C:
			a.tick(ctx)
		}
	}
}

// agent holds the steady-state loop state.
type agent struct {
	cfg     *config.Config
	client  *client.Client
	scanner *scan.Scanner

	assetIDs       map[string]string // "<host>:<port>" -> server asset id
	catalogVersion int               // last bundle version pulled
}

// tick performs one heartbeat and runs any returned jobs.
func (a *agent) tick(ctx context.Context) {
	resp, err := a.client.Heartbeat(ctx, a.cfg.AgentID, catalog.HeartbeatRequest{
		AgentVersion: version,
		Status:       "idle",
	})
	if err != nil {
		log.Printf("heartbeat: %v", err)
		return
	}
	if len(resp.Jobs) == 0 {
		return
	}
	log.Printf("heartbeat: %d job(s)", len(resp.Jobs))

	for _, job := range resp.Jobs {
		switch job.Type {
		case "discover":
			a.runDiscover(ctx, job)
		case "scan":
			a.runScan(ctx, job)
		default:
			log.Printf("job %s: unknown type %q, skipping", job.JobID, job.Type)
		}
	}
}

func (a *agent) runDiscover(ctx context.Context, job catalog.Job) {
	hostname, _ := os.Hostname()
	assets, err := discover.Discover(hostname, job.Payload.Scope)
	if err != nil {
		log.Printf("discover %s: %v", job.JobID, err)
		return
	}
	if len(assets) == 0 {
		log.Printf("discover %s: no listening services found", job.JobID)
		return
	}

	resp, err := a.client.SubmitAssets(ctx, a.cfg.AgentID, catalog.AssetsRequest{Assets: assets})
	if err != nil {
		log.Printf("discover %s: submit assets: %v", job.JobID, err)
		return
	}
	for k, v := range resp.AssetIDs {
		a.assetIDs[k] = v
	}
	log.Printf("discover %s: %d asset(s) reported", job.JobID, len(assets))
}

func (a *agent) runScan(ctx context.Context, job catalog.Job) {
	scanID := job.Payload.ScanID
	if scanID == "" {
		log.Printf("scan %s: missing scan_id, skipping", job.JobID)
		return
	}

	bundle, err := a.client.Bundle(ctx, a.catalogVersion)
	if err != nil {
		log.Printf("scan %s: pull catalog: %v", job.JobID, err)
		return
	}
	// Verify the bundle's Ed25519 signature against the pinned public key
	// before running ANY detection. Supply-chain integrity is load-bearing for
	// a security product.
	switch bundle.Signature {
	case "":
		log.Printf("scan %s: refusing to run, bundle signature is empty", job.JobID)
		return
	case "stub":
		log.Printf("scan %s: bundle is unsigned (dev mode), proceeding", job.JobID)
	default:
		pubkey := os.Getenv("PALISADE_CATALOG_PUBKEY")
		if pubkey == "" {
			pubkey = catalog.DemoPublicKeyB64
		}
		ok, err := catalog.VerifyBundle(bundle.Version, bundle.Detections, bundle.Signature, pubkey)
		if err != nil || !ok {
			log.Printf("scan %s: bundle signature verification FAILED, refusing to run detections", job.JobID)
			return
		}
		log.Printf("scan %s: bundle signature verified (%d detections)", job.JobID, len(bundle.Detections))
	}
	a.catalogVersion = bundle.Version

	byID := make(map[string]catalog.Detection, len(bundle.Detections))
	for _, d := range bundle.Detections {
		byID[d.ID] = d
	}

	hostname, _ := os.Hostname()
	// Reverse-map server asset ids to "<host>:<port>" so we can build a base URL.
	addrByAsset := make(map[string]string, len(a.assetIDs))
	for hp, id := range a.assetIDs {
		addrByAsset[id] = hp
	}

	var findings []catalog.FindingReport
	for _, t := range job.Payload.Targets {
		base := a.baseURLFor(t.AssetID, addrByAsset, hostname)
		fs := a.scanner.RunTarget(ctx, base, t, byID)
		for _, f := range fs {
			findings = append(findings, catalog.FindingReport{
				DetectionID: f.DetectionID,
				AssetID:     f.AssetID,
				Severity:    f.Severity,
				Fingerprint: f.Fingerprint,
				Evidence: catalog.Evidence{
					Request: f.Request,
					Note:    f.Note,
				},
			})
		}
	}

	if len(findings) == 0 {
		log.Printf("scan %s: no findings", job.JobID)
		return
	}
	if err := a.client.SubmitFindings(ctx, scanID, catalog.FindingsRequest{Findings: findings}); err != nil {
		log.Printf("scan %s: submit findings: %v", job.JobID, err)
		return
	}
	log.Printf("scan %s: %d finding(s) reported", job.JobID, len(findings))
}

// baseURLFor builds the target base URL for an asset. If we know the
// "<host>:<port>" from a prior discover, use it; otherwise fall back to the
// local hostname (the scan target is always on this host for the on-host
// model).
func (a *agent) baseURLFor(assetID string, addrByAsset map[string]string, hostname string) string {
	if hp, ok := addrByAsset[assetID]; ok {
		// Detections probe over HTTP. TODO: honor TLS / scheme hints from the
		// asset record once the contract carries them.
		return "http://" + hp
	}
	return "http://" + hostname
}
