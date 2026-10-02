package config

import (
	"path/filepath"
	"testing"
)

func TestResolveThemesDir(t *testing.T) {
	base := filepath.Join("data", "sso", "sso-server.json")
	got := ResolveThemesDir(base, "")
	want := filepath.Join(filepath.Dir(mustAbs(t, base)), "themes")
	if got != want {
		t.Fatalf("default: got %q want %q", got, want)
	}
	got = ResolveThemesDir(base, "custom-themes")
	want = filepath.Join(filepath.Dir(mustAbs(t, base)), "custom-themes")
	if got != want {
		t.Fatalf("relative: got %q want %q", got, want)
	}
	absThemes := filepath.Join(mustAbs(t, "."), "opt-themes")
	got = ResolveThemesDir(base, absThemes)
	if got != absThemes {
		t.Fatalf("absolute: got %q want %q", got, absThemes)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
