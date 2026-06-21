package scan

import (
	"net/http"
	"testing"
	"time"
)

func resp(status int, body string) response {
	return response{status: status, body: []byte(body), header: http.Header{}}
}

func TestEvalTyped_Regex(t *testing.T) {
	r := resp(200, `version 1.2.3 ready`)
	cases := []struct {
		name string
		m    matcher
		want bool
	}{
		{"match", matcher{Type: "regex", Regex: []string{`version \d+\.\d+\.\d+`}}, true},
		{"no-match", matcher{Type: "regex", Regex: []string{`error \d+`}}, false},
		{"all-must-match", matcher{Type: "regex", Regex: []string{`version`, `ready`}}, true},
		{"one-missing", matcher{Type: "regex", Regex: []string{`version`, `failed`}}, false},
		{"bad-pattern-fails-closed", matcher{Type: "regex", Regex: []string{`(`}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ok, _ := evalOne(c.m, r); ok != c.want {
				t.Errorf("got %v, want %v", ok, c.want)
			}
		})
	}
}

func TestEvalTyped_Binary(t *testing.T) {
	r := resp(200, "\x89PNG\r\n\x1a\n")
	cases := []struct {
		name string
		m    matcher
		want bool
	}{
		{"png-magic", matcher{Type: "binary", Binary: []string{"89504e47"}}, true},
		{"png-magic-0x", matcher{Type: "binary", Binary: []string{"0x89504e47"}}, true},
		{"no-match", matcher{Type: "binary", Binary: []string{"deadbeef"}}, false},
		{"bad-hex-fails-closed", matcher{Type: "binary", Binary: []string{"zz"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ok, _ := evalOne(c.m, r); ok != c.want {
				t.Errorf("got %v, want %v", ok, c.want)
			}
		})
	}
}

func TestEvalTyped_PartHeader(t *testing.T) {
	r := response{status: 200, body: []byte("not here"), header: http.Header{
		"Server": []string{"litellm/1.40.1"},
	}}
	if ok, _ := evalOne(matcher{Type: "word", Part: "header", Words: []string{"litellm"}}, r); !ok {
		t.Error("header word matcher should match Server header")
	}
	if ok, _ := evalOne(matcher{Type: "word", Part: "body", Words: []string{"litellm"}}, r); ok {
		t.Error("body word matcher should not match header content")
	}
	if ok, _ := evalOne(matcher{Type: "regex", Part: "header", Regex: []string{`litellm/\d`}}, r); !ok {
		t.Error("header regex matcher should match")
	}
}

func TestMatcherCondition(t *testing.T) {
	r := resp(500, `internal error`)
	good := matcher{Type: "status", Status: []int{500}}
	bad := matcher{Type: "word", Words: []string{"absent"}}

	if ok, key := evalMatcherSet([]matcher{good, bad}, condAnd, r); ok {
		t.Errorf("and: should fail when one fails, got ok=%v key=%q", ok, key)
	}
	if ok, _ := evalMatcherSet([]matcher{good, bad}, condOr, r); !ok {
		t.Error("or: should pass when one passes")
	}
	if ok, _ := evalMatcherSet([]matcher{bad, bad}, condOr, r); ok {
		t.Error("or: should fail when all fail")
	}
	// empty condition defaults to and
	if ok, _ := evalMatcherSet([]matcher{good}, "", r); !ok {
		t.Error("empty condition should default to and")
	}
	// unknown condition fails closed
	if ok, _ := evalMatcherSet([]matcher{good}, "xor", r); ok {
		t.Error("unknown condition should fail closed")
	}
}

func TestNegativeMatcher(t *testing.T) {
	r := resp(404, `not found`)
	// status 200 is absent; negated, the matcher passes.
	if ok, key := evalOne(matcher{Type: "status", Status: []int{200}, Negative: true}, r); !ok {
		t.Errorf("negated absent status should pass, got ok=%v key=%q", ok, key)
	}
	// status 404 is present; negated, the matcher fails.
	if ok, _ := evalOne(matcher{Type: "status", Status: []int{404}, Negative: true}, r); ok {
		t.Error("negated present status should fail")
	}
	// negated key is prefixed with "!"
	if _, key := evalOne(matcher{Type: "status", Status: []int{200}, Negative: true}, r); key != "!status" {
		t.Errorf("negated key = %q, want %q", key, "!status")
	}
}

func TestEvalDSLExpr_Helpers(t *testing.T) {
	r := response{status: 200, body: []byte("hello sql world"), header: http.Header{
		"X-Db": []string{"postgres"},
	}, elapsed: 5 * time.Second}

	cases := []struct {
		expr string
		want bool
	}{
		// duration (existing behavior preserved)
		{"duration>=5", true},
		{"duration < 5", false},
		// status
		{"status==200", true},
		{"status==500", false},
		{"status!=500", true},
		// len(body)
		{"len(body)>5", true},
		{"len(body)==15", true},
		{"len(body)<5", false},
		// string helpers
		{`contains(body,"sql")`, true},
		{`contains(body,"nope")`, false},
		{`startswith(body,"hello")`, true},
		{`startswith(body,"world")`, false},
		{`endswith(body,"world")`, true},
		{`endswith(body,"hello")`, false},
		{`regex("sql",body)`, true},
		{`regex("^hello",body)`, true},
		{`regex("^world",body)`, false},
		{`contains(header,"postgres")`, true},
		// commas inside string literals are honored
		{`contains(body,"sql world")`, true},
		// fail closed
		{"bogus", false},
		{"duration>=notanumber", false},
		{"unknownfn(body)", false},
		{`regex("(",body)`, false},
		{"", false},
		{"duration", false},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			if got := evalDSLExpr(c.expr, r); got != c.want {
				t.Errorf("evalDSLExpr(%q) = %v, want %v", c.expr, got, c.want)
			}
		})
	}
}
