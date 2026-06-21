package scan

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"palisade/agent/internal/catalog"
)

// flowResult is one request's captured response within a flow. Bodies stay
// local, same as the nuclei and compiled-module engines.
type flowResult struct {
	status int
	body   []byte
	header http.Header
}

// runFlow executes a declarative module-engine flow (approach B): it sends each
// request, captures the response keyed by request id, then requires every
// confirm expression to hold. Confirmed -> a Finding with a stable fingerprint
// keyed on the confirm expressions (not timing). Any unparseable confirm
// expression fails CLOSED (no match), matching the agent's safety posture.
func runFlow(ctx context.Context, base, assetID string, det catalog.Detection, hc *http.Client) (Finding, bool) {
	f := det.Flow
	if f == nil || len(f.Requests) == 0 || len(f.Confirm) == 0 {
		return Finding{}, false
	}

	results := make(map[string]flowResult, len(f.Requests))
	for _, r := range f.Requests {
		method := r.Method
		if method == "" {
			method = http.MethodGet
		}
		url := strings.TrimRight(base, "/") + r.Path
		var body io.Reader
		if r.Body != "" {
			body = strings.NewReader(r.Body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			log.Printf("scan: flow %s: build request %s %s: %v", det.ID, method, url, err)
			return Finding{}, false
		}
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
		if r.Body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := hc.Do(req)
		if err != nil {
			log.Printf("scan: flow %s: request %s %s: %v", det.ID, method, url, err)
			return Finding{}, false
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		// raw stays local; it is never sent upstream.
		results[r.ID] = flowResult{status: resp.StatusCode, body: raw, header: resp.Header}
	}

	for _, expr := range f.Confirm {
		if !evalConfirm(expr, results) {
			return Finding{}, false
		}
	}

	key := "flow:" + strings.Join(f.Confirm, ";")
	first := f.Requests[0]
	return Finding{
		DetectionID: det.ID,
		AssetID:     assetID,
		Severity:    det.Severity,
		Fingerprint: Fingerprint(assetID, det.ID, key),
		Request:     fmt.Sprintf("%s %s", first.Method, first.Path),
		Note:        "flow confirmed: " + strings.Join(f.Confirm, "; "),
	}, true
}

// evalConfirm evaluates one confirm expression against the captured results.
// Supported forms (anything else fails closed):
//
//	status(<id>) <op> N
//	len(body(<id>)) <op> N
//	contains(body(<id>), "literal")  /  contains(header(<id>), "literal")
//	regex("pattern", body(<id>))
func evalConfirm(expr string, results map[string]flowResult) bool {
	trimmed := strings.TrimSpace(expr)

	// Call forms end in ")"; parseCall/splitArgs are shared with the dsl helper.
	if name, args, ok := parseCall(trimmed); ok {
		switch name {
		case "contains":
			if len(args) != 2 {
				return confirmUnsupported(expr)
			}
			src, ok := flowSource(args[0], results)
			if !ok {
				return false
			}
			return strings.Contains(src, args[1])
		case "regex":
			if len(args) != 2 {
				return confirmUnsupported(expr)
			}
			re, err := regexp.Compile(args[0])
			if err != nil {
				log.Printf("scan: flow: bad regex %q: %v", args[0], err)
				return false
			}
			src, ok := flowSource(args[1], results)
			if !ok {
				return false
			}
			return re.MatchString(src)
		default:
			return confirmUnsupported(expr)
		}
	}

	// Comparison forms: status(id) op N | len(body(id)) op N.
	lhs, op, rhs, ok := splitComparison(strings.ReplaceAll(trimmed, " ", ""))
	if !ok {
		return confirmUnsupported(expr)
	}
	want, err := strconv.Atoi(rhs)
	if err != nil {
		log.Printf("scan: flow: bad operand in %q: %v", expr, err)
		return false
	}
	if id, ok := unwrap(lhs, "status"); ok {
		r, ok := results[id]
		if !ok {
			return false
		}
		return compareInt(r.status, op, want)
	}
	if inner, ok := unwrap(lhs, "len"); ok {
		if id, ok := unwrap(inner, "body"); ok {
			r, ok := results[id]
			if !ok {
				return false
			}
			return compareInt(len(r.body), op, want)
		}
	}
	return confirmUnsupported(expr)
}

// flowSource resolves a "body(<id>)" or "header(<id>)" argument to its text.
func flowSource(arg string, results map[string]flowResult) (string, bool) {
	if id, ok := unwrap(arg, "body"); ok {
		if r, ok := results[id]; ok {
			return string(r.body), true
		}
		return "", false
	}
	if id, ok := unwrap(arg, "header"); ok {
		if r, ok := results[id]; ok {
			return flowHeaderText(r.header), true
		}
		return "", false
	}
	return "", false
}

// unwrap returns the inner token of "name(inner)" and true, else "" and false.
func unwrap(s, name string) (string, bool) {
	prefix := name + "("
	if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, ")") {
		return s[len(prefix) : len(s)-1], true
	}
	return "", false
}

func flowHeaderText(h http.Header) string {
	var b strings.Builder
	for name, vals := range h {
		for _, v := range vals {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func confirmUnsupported(expr string) bool {
	log.Printf("scan: flow: unsupported confirm expression %q", expr)
	return false
}
