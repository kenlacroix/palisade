package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"palisade/agent/internal/catalog"
)

// flowServer mimics the Next.js middleware bypass: the protected route is gated
// (401) unless the request carries x-middleware-subrequest, which is served 200.
func flowServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-middleware-subrequest") != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin dashboard"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login required"))
	}))
}

func bypassFlow() *catalog.Flow {
	return &catalog.Flow{
		Requests: []catalog.FlowRequest{
			{ID: "baseline", Method: "GET", Path: "/dashboard"},
			{ID: "bypass", Method: "GET", Path: "/dashboard",
				Headers: map[string]string{"x-middleware-subrequest": "middleware"}},
		},
		Confirm: []string{"status(baseline) >= 400", "status(bypass) == 200"},
	}
}

func newFlowDet(f *catalog.Flow) catalog.Detection {
	return catalog.Detection{ID: "nextjs-flow", Engine: "module", Severity: "high", Flow: f}
}

func TestRunFlowConfirmed(t *testing.T) {
	srv := flowServer()
	defer srv.Close()
	hc := &http.Client{Timeout: 5 * time.Second}

	f, ok := runFlow(context.Background(), srv.URL, "asset-1", newFlowDet(bypassFlow()), hc)
	if !ok {
		t.Fatal("flow should confirm the bypass")
	}
	if f.DetectionID != "nextjs-flow" || f.Fingerprint == "" {
		t.Errorf("unexpected finding: %+v", f)
	}

	// Fingerprint is stable across runs (keyed on confirm exprs, not timing).
	f2, _ := runFlow(context.Background(), srv.URL, "asset-1", newFlowDet(bypassFlow()), hc)
	if f.Fingerprint != f2.Fingerprint {
		t.Errorf("fingerprint drifted: %q vs %q", f.Fingerprint, f2.Fingerprint)
	}
}

func TestRunFlowNegative(t *testing.T) {
	// Server that serves everyone 200 -> baseline is not gated, so no bypass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	hc := &http.Client{Timeout: 5 * time.Second}

	if _, ok := runFlow(context.Background(), srv.URL, "a", newFlowDet(bypassFlow()), hc); ok {
		t.Error("flow should not confirm when baseline is already open")
	}
}

func TestRunFlowFailsClosedOnBadExpr(t *testing.T) {
	srv := flowServer()
	defer srv.Close()
	hc := &http.Client{Timeout: 5 * time.Second}

	f := bypassFlow()
	f.Confirm = append(f.Confirm, "totally not a valid expr")
	if _, ok := runFlow(context.Background(), srv.URL, "a", newFlowDet(f), hc); ok {
		t.Error("an unparseable confirm expression must fail closed")
	}
}

func TestEvalConfirmForms(t *testing.T) {
	results := map[string]flowResult{
		"a": {status: 200, body: []byte("hello world"), header: http.Header{"X-Test": {"yes"}}},
		"b": {status: 401, body: []byte("")},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"status(a) == 200", true},
		{"status(b) >= 400", true},
		{"status(a) != 200", false},
		{"len(body(a)) > 5", true},
		{"len(body(b)) == 0", true},
		{`contains(body(a), "world")`, true},
		{`contains(body(a), "absent")`, false},
		{`regex("h.llo", body(a))`, true},
		{`contains(header(a), "yes")`, true},
		{"status(missing) == 200", false}, // unknown id -> fail closed
		{"bogus(a) == 1", false},          // unsupported lhs -> fail closed
		{"status(a) ~= 200", false},       // bad operator -> fail closed
	}
	for _, c := range cases {
		if got := evalConfirm(c.expr, results); got != c.want {
			t.Errorf("evalConfirm(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}
