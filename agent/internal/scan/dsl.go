package scan

import (
	"encoding/hex"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"palisade/agent/internal/catalog"
)

// matcher is the scan-package matcher model. It is a superset of
// catalog.Matcher: it carries the wire fields plus the expanded nuclei subset
// the agent supports (regex/binary types, a body|header part selector, and a
// negative flag). Real detections arrive as catalog.Matcher and are widened via
// fromCatalog; the extra fields default to their zero values, so existing
// detections keep their current behavior.
type matcher struct {
	Type     string
	DSL      []string
	Words    []string
	Status   []int
	Regex    []string // when Type == "regex"
	Binary   []string // when Type == "binary": hex byte sequences
	Part     string   // "body" (default) | "header"
	Negative bool     // invert the matcher result
}

// fromCatalog widens a wire matcher to the scan model.
func fromCatalog(m catalog.Matcher) matcher {
	return matcher{Type: m.Type, DSL: m.DSL, Words: m.Words, Status: m.Status}
}

// response is the part of an HTTP response matchers run against. Bodies stay
// local; nothing here is reported upstream.
type response struct {
	status  int
	body    []byte
	header  http.Header
	elapsed time.Duration
}

// matcherCondition is the AND/OR combinator across a step's matcher list. An
// empty value means AND, preserving the nuclei default and prior behavior.
const (
	condAnd = "and"
	condOr  = "or"
)

// evalMatcherSet evaluates ms under the given condition and returns whether the
// set passed and the first contributing matcher key (for the fingerprint).
func evalMatcherSet(ms []matcher, cond string, r response) (bool, string) {
	if len(ms) == 0 {
		return false, ""
	}
	if cond == "" {
		cond = condAnd
	}
	firstKey := ""
	anyMatched := false
	for _, m := range ms {
		ok, key := evalOne(m, r)
		switch cond {
		case condOr:
			if ok {
				return true, key
			}
		case condAnd:
			if !ok {
				return false, ""
			}
			anyMatched = true
			if firstKey == "" {
				firstKey = key
			}
		default:
			log.Printf("scan: unknown matcher-condition %q, treating as no-match", cond)
			return false, ""
		}
	}
	if cond == condOr {
		return false, ""
	}
	return anyMatched, firstKey
}

// evalOne evaluates a single matcher, applying the negative flag. A negated
// matcher that would have matched returns false (and vice versa); its key is
// prefixed with "!" so the fingerprint reflects the inversion.
func evalOne(m matcher, r response) (bool, string) {
	ok, key := evalTyped(m, r)
	if m.Negative {
		if key == "" {
			key = "!" + m.Type
		} else {
			key = "!" + key
		}
		return !ok, key
	}
	return ok, key
}

// partText returns the text the matcher runs against for its part selector.
func partText(part string, r response) string {
	if part == "header" {
		var b strings.Builder
		for name, vals := range r.header {
			for _, v := range vals {
				b.WriteString(name)
				b.WriteString(": ")
				b.WriteString(v)
				b.WriteByte('\n')
			}
		}
		return b.String()
	}
	return string(r.body)
}

func evalTyped(m matcher, r response) (bool, string) {
	switch m.Type {
	case "dsl":
		for _, expr := range m.DSL {
			if !evalDSLExpr(expr, r) {
				return false, ""
			}
		}
		return true, "dsl:" + strings.Join(m.DSL, ",")
	case "word":
		text := partText(m.Part, r)
		for _, w := range m.Words {
			if !strings.Contains(text, w) {
				return false, ""
			}
		}
		return true, "word:" + strings.Join(m.Words, ",")
	case "regex":
		text := partText(m.Part, r)
		for _, pat := range m.Regex {
			re, err := regexp.Compile(pat)
			if err != nil {
				log.Printf("scan: bad regex %q: %v", pat, err)
				return false, ""
			}
			if !re.MatchString(text) {
				return false, ""
			}
		}
		return true, "regex:" + strings.Join(m.Regex, ",")
	case "binary":
		text := partText(m.Part, r)
		for _, h := range m.Binary {
			b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
			if err != nil {
				log.Printf("scan: bad binary %q: %v", h, err)
				return false, ""
			}
			if !strings.Contains(text, string(b)) {
				return false, ""
			}
		}
		return true, "binary:" + strings.Join(m.Binary, ",")
	case "status":
		for _, code := range m.Status {
			if code == r.status {
				return true, "status:" + strconv.Itoa(r.status)
			}
		}
		return false, ""
	default:
		log.Printf("scan: unknown matcher type %q, treating as no-match", m.Type)
		return false, ""
	}
}

// evalDSLExpr evaluates a single nuclei-style dsl expression. It supports a
// bounded, hand-rolled subset: duration comparisons, status==N, len(body)
// comparisons, and the string helpers contains/regex/startswith/endswith.
// Anything outside the subset fails CLOSED (no-match), matching the agent's
// safety posture. No external expression-language dependency is used.
func evalDSLExpr(expr string, r response) bool {
	trimmed := strings.TrimSpace(expr)

	// Helper-call forms: name(args). Whitespace inside string literals is
	// preserved; only the structural form is parsed.
	if fn, args, ok := parseCall(trimmed); ok {
		switch fn {
		case "contains":
			if len(args) != 2 {
				return dslUnsupported(expr)
			}
			return strings.Contains(dslSource(args[0], r), args[1])
		case "startswith":
			if len(args) != 2 {
				return dslUnsupported(expr)
			}
			return strings.HasPrefix(dslSource(args[0], r), args[1])
		case "endswith":
			if len(args) != 2 {
				return dslUnsupported(expr)
			}
			return strings.HasSuffix(dslSource(args[0], r), args[1])
		case "regex":
			if len(args) != 2 {
				return dslUnsupported(expr)
			}
			re, err := regexp.Compile(args[0])
			if err != nil {
				log.Printf("scan: bad dsl regex %q: %v", args[0], err)
				return false
			}
			return re.MatchString(dslSource(args[1], r))
		default:
			return dslUnsupported(expr)
		}
	}

	// Comparison forms: <lhs><op><rhs> with no spaces.
	noSpace := strings.ReplaceAll(trimmed, " ", "")
	lhs, op, rhs, ok := splitComparison(noSpace)
	if !ok {
		return dslUnsupported(expr)
	}

	switch {
	case lhs == "duration":
		want, err := strconv.ParseFloat(rhs, 64)
		if err != nil {
			return dslBadOperand(expr, err)
		}
		return compareFloat(r.elapsed.Seconds(), op, want)
	case lhs == "status":
		want, err := strconv.Atoi(rhs)
		if err != nil {
			return dslBadOperand(expr, err)
		}
		return compareInt(r.status, op, want)
	case lhs == "len(body)":
		want, err := strconv.Atoi(rhs)
		if err != nil {
			return dslBadOperand(expr, err)
		}
		return compareInt(len(r.body), op, want)
	default:
		return dslUnsupported(expr)
	}
}

func dslUnsupported(expr string) bool {
	log.Printf("scan: unsupported dsl expression %q", expr)
	return false
}

func dslBadOperand(expr string, err error) bool {
	log.Printf("scan: bad dsl operand in %q: %v", expr, err)
	return false
}

// dslSource resolves a dsl argument to its source text. The bareword "body"
// resolves to the response body; "header" to the serialized headers; anything
// else is treated as a literal (already unquoted by parseCall).
func dslSource(arg string, r response) string {
	switch arg {
	case "body":
		return string(r.body)
	case "header":
		return partText("header", r)
	default:
		return arg
	}
}

// parseCall parses "name(arg1,arg2)" into the function name and its arguments.
// String literals may be single- or double-quoted; barewords are returned
// verbatim. Returns ok=false when the input is not a call form.
func parseCall(s string) (string, []string, bool) {
	open := strings.IndexByte(s, '(')
	if open <= 0 || !strings.HasSuffix(s, ")") {
		return "", nil, false
	}
	name := s[:open]
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') {
			return "", nil, false
		}
	}
	inner := s[open+1 : len(s)-1]
	args, ok := splitArgs(inner)
	if !ok {
		return "", nil, false
	}
	return name, args, true
}

// splitArgs splits a comma-separated argument list, honoring quoted literals so
// commas inside strings are not treated as separators. Quotes are stripped from
// literal arguments; barewords and surrounding whitespace are trimmed.
func splitArgs(s string) ([]string, bool) {
	var args []string
	var cur strings.Builder
	var quote byte
	inQuote := false
	flush := func() string {
		return strings.TrimSpace(cur.String())
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quote {
				inQuote = false
				args = append(args, cur.String())
				cur.Reset()
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = true
			quote = c
			cur.Reset()
		case ',':
			if v := flush(); v != "" {
				args = append(args, v)
			}
			cur.Reset()
		case ' ', '\t':
			// skip structural whitespace between args
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, false
	}
	if v := flush(); v != "" {
		args = append(args, v)
	}
	return args, true
}

// splitComparison splits a space-free "<lhs><op><rhs>" expression. The operator
// is matched longest-first so ">=" is preferred over ">".
func splitComparison(s string) (lhs, op, rhs string, ok bool) {
	for _, candidate := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if i := strings.Index(s, candidate); i > 0 {
			return s[:i], candidate, s[i+len(candidate):], true
		}
	}
	return "", "", "", false
}

func compareFloat(got float64, op string, want float64) bool {
	switch op {
	case ">=":
		return got >= want
	case "<=":
		return got <= want
	case "==":
		return got == want
	case "!=":
		return got != want
	case ">":
		return got > want
	case "<":
		return got < want
	}
	return false
}

func compareInt(got int, op string, want int) bool {
	switch op {
	case ">=":
		return got >= want
	case "<=":
		return got <= want
	case "==":
		return got == want
	case "!=":
		return got != want
	case ">":
		return got > want
	case "<":
		return got < want
	}
	return false
}
