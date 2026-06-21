// Package scan executes detections against discovered assets. Detection logic
// runs on-host: requests and raw response bodies stay local; only normalized
// findings are reported upstream.
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"palisade/agent/internal/catalog"
)

// maxBody caps how much of a response body is read into memory for matching.
const maxBody = 1 << 20 // 1 MiB

// Finding is the in-memory result of a matched detection before it is
// normalized into a catalog.FindingReport.
type Finding struct {
	DetectionID string
	AssetID     string
	Severity    string
	Fingerprint string
	Request     string
	Note        string
}

// Scanner runs detections over HTTP.
type Scanner struct {
	hc *http.Client
}

// New returns a Scanner with sane request timeouts. The timeout must exceed
// the longest duration-based DSL check (e.g. SQLi sleep payloads).
func New() *Scanner {
	return &Scanner{hc: &http.Client{Timeout: 30 * time.Second}}
}

// Fingerprint is the stable finding key: sha256_hex(asset_id|detection_id|key).
func Fingerprint(assetID, detectionID, evidenceKey string) string {
	h := sha256.Sum256([]byte(assetID + "|" + detectionID + "|" + evidenceKey))
	return hex.EncodeToString(h[:])
}

// RunTarget evaluates every detection in a target against the asset at base
// (e.g. "http://host:port") and returns matched findings.
func (s *Scanner) RunTarget(ctx context.Context, base string, t catalog.ScanTarget, byID map[string]catalog.Detection) []Finding {
	var out []Finding
	for _, did := range t.DetectionIDs {
		det, ok := byID[did]
		if !ok {
			log.Printf("scan: detection %q not in bundle, skipping", did)
			continue
		}
		if det.Engine == "module" {
			// Module detections run compiled multi-step logic referenced by
			// spec_ref. The module ships in this binary, not the catalog.
			mod, ok := lookupModule(det.SpecRef)
			if !ok {
				log.Printf("scan: detection %q references module %q which is not registered, skipping", det.ID, det.SpecRef)
				continue
			}
			if f, ok := mod.Run(ctx, ModuleEnv{Base: base, AssetID: t.AssetID, Det: det, HC: s.hc}); ok {
				out = append(out, f)
			}
			continue
		}
		if f, ok := s.runNuclei(ctx, base, t.AssetID, det); ok {
			out = append(out, f)
		}
	}
	return out
}

// runNuclei runs the http steps of a nuclei-engine detection. On the first
// step whose matchers all pass, it returns a Finding.
func (s *Scanner) runNuclei(ctx context.Context, base, assetID string, det catalog.Detection) (Finding, bool) {
	for _, step := range det.HTTP {
		url := strings.TrimRight(base, "/") + step.Path
		var body io.Reader
		if step.Body != "" {
			body = strings.NewReader(step.Body)
		}
		req, err := http.NewRequestWithContext(ctx, step.Method, url, body)
		if err != nil {
			log.Printf("scan: build request %s %s: %v", step.Method, url, err)
			continue
		}
		if step.Body != "" {
			req.Header.Set("Content-Type", "application/json")
		}

		start := time.Now()
		resp, err := s.hc.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			log.Printf("scan: request %s %s: %v", step.Method, url, err)
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		// raw stays local; it is never sent upstream.

		matched, key := evalMatchers(step.Matchers, response{
			status:  resp.StatusCode,
			body:    raw,
			header:  resp.Header,
			elapsed: elapsed,
		})
		if !matched {
			continue
		}
		reqLine := fmt.Sprintf("%s %s", step.Method, step.Path)
		return Finding{
			DetectionID: det.ID,
			AssetID:     assetID,
			Severity:    det.Severity,
			Fingerprint: Fingerprint(assetID, det.ID, key),
			Request:     reqLine,
			Note:        fmt.Sprintf("matched %s in %s", key, elapsed.Round(time.Millisecond)),
		}, true
	}
	return Finding{}, false
}

// evalMatchers evaluates a step's wire matchers against a response. Wire
// matchers are ANDed (nuclei default); the expanded matcher model and the
// or-condition combinator are reached via evalMatcherSet (see dsl.go).
func evalMatchers(ms []catalog.Matcher, r response) (bool, string) {
	conv := make([]matcher, len(ms))
	for i, m := range ms {
		conv[i] = fromCatalog(m)
	}
	return evalMatcherSet(conv, condAnd, r)
}

// evalDSL evaluates a single dsl expression for a duration-only response. It is
// retained as a thin wrapper over the full evaluator (see evalDSLExpr in
// dsl.go) for duration-based callers and tests.
func evalDSL(expr string, elapsed time.Duration) bool {
	return evalDSLExpr(expr, response{elapsed: elapsed})
}
