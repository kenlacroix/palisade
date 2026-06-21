package scan

import (
	"testing"
	"time"

	"palisade/agent/internal/catalog"
)

func TestFingerprint(t *testing.T) {
	// Stable, deterministic, lowercase hex of length 64.
	got := Fingerprint("asset1", "det1", "dsl:duration>=5")
	if len(got) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(got))
	}
	if got != Fingerprint("asset1", "det1", "dsl:duration>=5") {
		t.Error("fingerprint is not deterministic")
	}
	if got == Fingerprint("asset2", "det1", "dsl:duration>=5") {
		t.Error("fingerprint should change with asset id")
	}
}

func TestEvalDSLDuration(t *testing.T) {
	cases := []struct {
		expr    string
		elapsed time.Duration
		want    bool
	}{
		{"duration>=5", 5 * time.Second, true},
		{"duration>=5", 4 * time.Second, false},
		{"duration > 5", 6 * time.Second, true},
		{"duration<1", 500 * time.Millisecond, true},
		{"duration<=2", 3 * time.Second, false},
		{"bogus", time.Second, false},
	}
	for _, c := range cases {
		if got := evalDSL(c.expr, c.elapsed); got != c.want {
			t.Errorf("evalDSL(%q, %s) = %v, want %v", c.expr, c.elapsed, got, c.want)
		}
	}
}

func TestEvalMatchers(t *testing.T) {
	body := []byte(`{"error":"sql syntax"}`)
	r := func(status int, elapsed time.Duration) response {
		return response{status: status, body: body, elapsed: elapsed}
	}

	// status matches
	ok, key := evalMatchers([]catalog.Matcher{{Type: "status", Status: []int{200, 500}}}, r(500, 0))
	if !ok || key != "status:500" {
		t.Errorf("status matcher: ok=%v key=%q", ok, key)
	}

	// word matches all
	ok, _ = evalMatchers([]catalog.Matcher{{Type: "word", Words: []string{"sql", "error"}}}, r(200, 0))
	if !ok {
		t.Error("word matcher should match")
	}

	// word fails if any missing
	ok, _ = evalMatchers([]catalog.Matcher{{Type: "word", Words: []string{"sql", "absent"}}}, r(200, 0))
	if ok {
		t.Error("word matcher should fail on missing word")
	}

	// dsl duration
	ok, _ = evalMatchers([]catalog.Matcher{{Type: "dsl", DSL: []string{"duration>=5"}}}, r(200, 5*time.Second))
	if !ok {
		t.Error("dsl matcher should match on slow response")
	}

	// AND: both must pass
	ms := []catalog.Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "dsl", DSL: []string{"duration>=5"}},
	}
	ok, key = evalMatchers(ms, r(200, 5*time.Second))
	if !ok || key != "status:200" {
		t.Errorf("AND matchers: ok=%v key=%q (want first key status:200)", ok, key)
	}
	ok, _ = evalMatchers(ms, r(200, time.Second))
	if ok {
		t.Error("AND matchers should fail when dsl fails")
	}
}
