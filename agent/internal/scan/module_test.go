package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"palisade/agent/internal/catalog"
)

func TestModuleRegistryDispatch(t *testing.T) {
	if _, ok := lookupModule("modules/nextjs_middleware_bypass"); !ok {
		t.Fatal("nextjs module not registered")
	}
	if _, ok := lookupModule("modules/does-not-exist"); ok {
		t.Error("unknown spec_ref should not resolve")
	}
}

// vulnerable Next.js: middleware redirects to /login, but the subrequest header
// skips it and returns 200.
func TestNextjsBypassVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-middleware-subrequest") != "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	f, ok := runModule(t, srv.URL)
	if !ok {
		t.Fatal("expected the bypass to be detected")
	}
	if f.DetectionID != "nextjs-middleware-bypass" || f.Fingerprint == "" {
		t.Errorf("unexpected finding: %+v", f)
	}
}

// patched Next.js: the header is ignored, middleware still redirects.
func TestNextjsBypassPatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	if _, ok := runModule(t, srv.URL); ok {
		t.Error("patched server must not be flagged")
	}
}

// no middleware gate: root is already 200, so there is nothing to bypass.
func TestNextjsBypassNoGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, ok := runModule(t, srv.URL); ok {
		t.Error("open app without a gate must not be flagged")
	}
}

func runModule(t *testing.T, base string) (Finding, bool) {
	t.Helper()
	s := New()
	det := catalog.Detection{ID: "nextjs-middleware-bypass", Engine: "module", Severity: "high", SpecRef: "modules/nextjs_middleware_bypass"}
	target := catalog.ScanTarget{AssetID: "asset-1", DetectionIDs: []string{det.ID}}
	out := s.RunTarget(context.Background(), base, target, map[string]catalog.Detection{det.ID: det})
	if len(out) == 0 {
		return Finding{}, false
	}
	return out[0], true
}
