package catalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DemoPublicKeyB64 is the pinned demo signing public key (base64-std, raw 32 bytes).
const DemoPublicKeyB64 = "DRLpngzapOzExqzZsykc6h8LTpuGjw3ahrGJvnMwFhY="

// Canonical separator bytes.
const (
	sepUS = 0x1f // unit separator: between detection fields
	sepRS = 0x1e // record separator: between http steps
	sepGS = 0x1d // group separator: between matchers
	sepSP = 0x20 // space: within an http step
)

// detectionString builds the canonical per-detection string D.
func detectionString(d Detection) []byte {
	var b bytes.Buffer
	writeField := func(s string, first bool) {
		if !first {
			b.WriteByte(sepUS)
		}
		b.WriteString(s)
	}
	writeField(d.ID, true)
	writeField(d.CVE, false)
	writeField(d.Severity, false)
	writeField(d.Category, false)
	writeField(d.Engine, false)
	writeField(d.Match.Service, false)
	writeField(d.Match.Versions, false)
	writeField(d.SpecRef, false)
	writeField(d.Remediation, false)
	writeField(httpString(d), false)
	return b.Bytes()
}

// httpString builds the canonical HTTP segment for a detection.
func httpString(d Detection) string {
	if d.Engine != "nuclei" || len(d.HTTP) == 0 {
		return ""
	}
	steps := make([]string, 0, len(d.HTTP))
	for _, step := range d.HTTP {
		var sb strings.Builder
		sb.WriteString(step.Method)
		sb.WriteByte(sepSP)
		sb.WriteString(step.Path)
		sb.WriteByte(sepSP)
		sb.WriteString(step.Body)
		sb.WriteByte(sepSP)
		sb.WriteString(matchersString(step.Matchers))
		steps = append(steps, sb.String())
	}
	return strings.Join(steps, string(rune(sepRS)))
}

// matchersString joins matchers by GS.
func matchersString(ms []Matcher) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		var values string
		switch m.Type {
		case "dsl":
			values = strings.Join(m.DSL, ",")
		case "word":
			values = strings.Join(m.Words, ",")
		case "status":
			ss := make([]string, len(m.Status))
			for i, code := range m.Status {
				ss[i] = strconv.Itoa(code)
			}
			values = strings.Join(ss, ",")
		default:
			values = ""
		}
		parts = append(parts, m.Type+":"+values)
	}
	return strings.Join(parts, string(rune(sepGS)))
}

// BuildManifest returns the canonical signed bytes for a bundle.
func BuildManifest(version int, dets []Detection) []byte {
	sorted := make([]Detection, len(dets))
	copy(sorted, dets)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	hashes := make([]string, len(sorted))
	for i, d := range sorted {
		sum := sha256.Sum256(detectionString(d))
		hashes[i] = hex.EncodeToString(sum[:])
	}

	var m bytes.Buffer
	m.WriteString("palisade-catalog-v1\n")
	m.WriteString(strconv.Itoa(version))
	m.WriteByte('\n')
	m.WriteString(strings.Join(hashes, "\n"))
	return m.Bytes()
}

// VerifyBundle verifies sigB64 over the bundle manifest using pubB64 (base64 raw ed25519 pubkey).
func VerifyBundle(version int, dets []Detection, sigB64, pubB64 string) (bool, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	m := BuildManifest(version, dets)
	return ed25519.Verify(ed25519.PublicKey(pub), m, sig), nil
}
