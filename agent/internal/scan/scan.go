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
	"strconv"
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
			// TODO(module-engine): execute the compiled Go module referenced
			// by det.SpecRef. Custom modules cover multi-step logic Nuclei
			// cannot express (auth-bypass chains, stateful PoCs).
			log.Printf("scan: detection %q uses module engine (spec_ref=%q): module engine not implemented", det.ID, det.SpecRef)
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

		matched, key := evalMatchers(step.Matchers, resp.StatusCode, raw, elapsed)
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

// evalMatchers returns whether all matchers pass and the first matcher key
// used for the fingerprint. Matchers are ANDed (nuclei default).
func evalMatchers(ms []catalog.Matcher, status int, body []byte, elapsed time.Duration) (bool, string) {
	if len(ms) == 0 {
		return false, ""
	}
	firstKey := ""
	for _, m := range ms {
		ok, key := evalMatcher(m, status, body, elapsed)
		if !ok {
			return false, ""
		}
		if firstKey == "" {
			firstKey = key
		}
	}
	return true, firstKey
}

func evalMatcher(m catalog.Matcher, status int, body []byte, elapsed time.Duration) (bool, string) {
	switch m.Type {
	case "dsl":
		for _, expr := range m.DSL {
			if !evalDSL(expr, elapsed) {
				return false, ""
			}
		}
		return true, "dsl:" + strings.Join(m.DSL, ",")
	case "word":
		text := string(body)
		for _, w := range m.Words {
			if !strings.Contains(text, w) {
				return false, ""
			}
		}
		return true, "word:" + strings.Join(m.Words, ",")
	case "status":
		for _, code := range m.Status {
			if code == status {
				return true, "status:" + strconv.Itoa(status)
			}
		}
		return false, ""
	default:
		log.Printf("scan: unknown matcher type %q, treating as no-match", m.Type)
		return false, ""
	}
}

// evalDSL supports duration comparisons of the form "duration>=N",
// "duration>N", "duration<=N", "duration<N", "duration==N" where N is seconds
// (int or float). This is the subset needed for time-based detections (e.g.
// blind SQLi sleep payloads). Anything else is unsupported and fails closed.
//
// TODO(dsl): expand to the full nuclei DSL (string/header helpers, logic ops).
func evalDSL(expr string, elapsed time.Duration) bool {
	expr = strings.ReplaceAll(expr, " ", "")
	const key = "duration"
	if !strings.HasPrefix(expr, key) {
		log.Printf("scan: unsupported dsl expression %q", expr)
		return false
	}
	rest := expr[len(key):]

	var op string
	for _, candidate := range []string{">=", "<=", "==", ">", "<"} {
		if strings.HasPrefix(rest, candidate) {
			op = candidate
			break
		}
	}
	if op == "" {
		log.Printf("scan: unsupported dsl operator in %q", expr)
		return false
	}

	want, err := strconv.ParseFloat(rest[len(op):], 64)
	if err != nil {
		log.Printf("scan: bad dsl threshold in %q: %v", expr, err)
		return false
	}

	got := elapsed.Seconds()
	switch op {
	case ">=":
		return got >= want
	case "<=":
		return got <= want
	case "==":
		return got == want
	case ">":
		return got > want
	case "<":
		return got < want
	}
	return false
}
