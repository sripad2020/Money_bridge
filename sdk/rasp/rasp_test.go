package rasp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuardFindsRootArtefactAndModifiedBinary(t *testing.T) {
	dir := t.TempDir()
	su := filepath.Join(dir, "su")
	if err := os.WriteFile(su, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := New(Config{RootPaths: []string{su}, ExpectedBinarySHA256: "00", Disable: []string{"debugger"}})
	r := g.Check()
	if !r.Critical() {
		t.Fatalf("expected critical findings, got %+v", r.Findings)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Check] = true
	}
	if !got["root"] || !got["integrity"] {
		t.Fatalf("missing root or integrity finding: %+v", r.Findings)
	}
}

func TestCleanEnvironmentHasNoCriticalFindings(t *testing.T) {
	r := New(Config{RootPaths: []string{filepath.Join(t.TempDir(), "absent")}}).Check()
	if r.Critical() {
		t.Fatalf("clean test process flagged: %+v", r.Findings)
	}
}

func TestStaticGuard(t *testing.T) {
	if !(Static{Findings: nil}).Check().Critical() == false {
		t.Fatal("empty static guard should not be critical")
	}
}
