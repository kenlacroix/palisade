package main

import (
	"os"
	"testing"
)

func TestResolveEnrollToken(t *testing.T) {
	t.Run("env wins over flag", func(t *testing.T) {
		t.Setenv("PALISADE_ENROLL_TOKEN", "env-tok")
		got, err := resolveEnrollToken("flag-tok", false)
		if err != nil {
			t.Fatal(err)
		}
		if got != "env-tok" {
			t.Fatalf("want env-tok, got %q", got)
		}
	})

	t.Run("flag used when env unset", func(t *testing.T) {
		t.Setenv("PALISADE_ENROLL_TOKEN", "")
		got, err := resolveEnrollToken("flag-tok", false)
		if err != nil {
			t.Fatal(err)
		}
		if got != "flag-tok" {
			t.Fatalf("want flag-tok, got %q", got)
		}
	})

	t.Run("stdin wins and is trimmed", func(t *testing.T) {
		t.Setenv("PALISADE_ENROLL_TOKEN", "env-tok")
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString("  stdin-tok\n"); err != nil {
			t.Fatal(err)
		}
		w.Close()
		old := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = old }()

		got, err := resolveEnrollToken("flag-tok", true)
		if err != nil {
			t.Fatal(err)
		}
		if got != "stdin-tok" {
			t.Fatalf("want stdin-tok, got %q", got)
		}
	})
}
