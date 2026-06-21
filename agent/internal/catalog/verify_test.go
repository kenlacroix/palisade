package catalog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// demoSeedB64 is the base64 raw 32-byte Ed25519 seed whose public key is
// DemoPublicKeyB64 (see control-plane signing.py DEMO_SEED_B64). Public dev key.
const demoSeedB64 = "70kJtI1NajTd1yQXFHVRuBVQfc6P2CAtRroaLCmYYbY="

func signWithDemoSeed(t *testing.T, version int, dets []Detection) string {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(demoSeedB64)
	if err != nil {
		t.Fatalf("decode demo seed: %v", err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), BuildManifest(version, dets))
	return base64.StdEncoding.EncodeToString(sig)
}

func sampleDetections() []Detection {
	return []Detection{
		{
			ID:       "det-nuclei",
			CVE:      "CVE-2024-0001",
			Severity: "critical",
			Category: "web",
			Engine:   "nuclei",
			Match:    Match{Service: "http", Versions: ">=1.0 <2.0"},
			HTTP: []HTTPStep{
				{
					Method: "GET",
					Path:   "/admin",
					Body:   "",
					Matchers: []Matcher{
						{Type: "status", Status: []int{200, 401}},
						{Type: "word", Words: []string{"unauthorized", "forbidden"}},
						{Type: "dsl", DSL: []string{"contains(body,'x')"}},
					},
				},
				{
					Method: "POST",
					Path:   "/login",
					Body:   "user=admin",
					Matchers: []Matcher{
						{Type: "status", Status: []int{302}},
					},
				},
			},
			Remediation: "patch it",
		},
		{
			ID:          "det-module",
			Severity:    "high",
			Category:    "ai-infra",
			Engine:      "module",
			Match:       Match{Service: "ollama", Versions: "*"},
			SpecRef:     "spec://ollama-open",
			Remediation: "restrict access",
		},
	}
}

func TestBuildManifestOrderIndependent(t *testing.T) {
	dets := sampleDetections()
	shuffled := []Detection{dets[1], dets[0]}

	m1 := BuildManifest(7, dets)
	m2 := BuildManifest(7, shuffled)
	if !bytes.Equal(m1, m2) {
		t.Fatalf("manifest depends on input order:\n%q\n%q", m1, m2)
	}
}

func TestBuildManifestDeterministic(t *testing.T) {
	dets := sampleDetections()
	if !bytes.Equal(BuildManifest(7, dets), BuildManifest(7, dets)) {
		t.Fatal("manifest not deterministic across calls")
	}
}

func TestBuildManifestDoesNotMutateInput(t *testing.T) {
	dets := sampleDetections()
	before := dets[0].ID
	_ = BuildManifest(7, dets)
	if dets[0].ID != before {
		t.Fatalf("BuildManifest mutated input order: got %q want %q", dets[0].ID, before)
	}
}

func TestTamperChangesManifest(t *testing.T) {
	base := BuildManifest(7, sampleDetections())

	tests := []struct {
		name   string
		mutate func(d []Detection)
	}{
		{"path", func(d []Detection) { d[0].HTTP[0].Path = "/changed" }},
		{"versions", func(d []Detection) { d[1].Match.Versions = "1.2.3" }},
		{"version-int", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "version-int" {
				if bytes.Equal(base, BuildManifest(8, sampleDetections())) {
					t.Fatal("changing version did not change manifest")
				}
				return
			}
			dets := sampleDetections()
			tc.mutate(dets)
			if bytes.Equal(base, BuildManifest(7, dets)) {
				t.Fatalf("tampering with %s did not change manifest", tc.name)
			}
		})
	}
}

func TestVerifyBundleSignedThenTamperedRejected(t *testing.T) {
	dets := sampleDetections()
	sig := signWithDemoSeed(t, 7, dets)

	if ok, err := VerifyBundle(7, dets, sig, DemoPublicKeyB64); err != nil || !ok {
		t.Fatalf("expected valid signature to verify, got ok=%v err=%v", ok, err)
	}

	// Same signature, a detection mutated after signing: must be rejected.
	tampered := sampleDetections()
	tampered[0].Remediation += " TAMPERED"
	if ok, _ := VerifyBundle(7, tampered, sig, DemoPublicKeyB64); ok {
		t.Fatal("expected tampered bundle to be rejected")
	}

	// The signature covers the version too.
	if ok, _ := VerifyBundle(8, dets, sig, DemoPublicKeyB64); ok {
		t.Fatal("expected version mismatch to be rejected")
	}
}

func TestVerifyBundleBadInputs(t *testing.T) {
	dets := sampleDetections()

	// Invalid base64 signature.
	if ok, err := VerifyBundle(7, dets, "!!!not-base64!!!", DemoPublicKeyB64); err == nil || ok {
		t.Fatalf("expected error for invalid base64 signature, got ok=%v err=%v", ok, err)
	}

	// Invalid base64 public key.
	if ok, err := VerifyBundle(7, dets, "AAAA", "!!!not-base64!!!"); err == nil || ok {
		t.Fatalf("expected error for invalid base64 pubkey, got ok=%v err=%v", ok, err)
	}

	// Well-formed base64 but wrong-size / bogus signature against the pinned key.
	// 64 zero bytes base64-encoded; valid base64, valid length, but wrong sig.
	bogus := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ok, err := VerifyBundle(7, dets, bogus, DemoPublicKeyB64)
	if err != nil {
		t.Fatalf("unexpected error for well-formed bogus sig: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for bogus signature")
	}
}
