package token

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenSCModeFiltersVendorDriversAndDefaultKeepsFallback(t *testing.T) {
	original := drivers[runtime.GOOS]
	defer func() { drivers[runtime.GOOS] = original }()
	directory := t.TempDir()
	vendor := filepath.Join(directory, "vendor.dll")
	opensc := filepath.Join(directory, "opensc-pkcs11.dll")
	for _, path := range []string{vendor, opensc} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	drivers[runtime.GOOS] = []string{vendor, opensc, filepath.Join(directory, "missing")}
	selected := Drivers("opensc")
	if len(selected) != 1 || selected[0] != opensc {
		t.Fatalf("OpenSC selection: %v", selected)
	}
	if got := Drivers(""); len(got) != 2 {
		t.Fatalf("automatic fallback missing: %v", got)
	}
	if got := Drivers(vendor); len(got) != 1 || got[0] != vendor {
		t.Fatalf("explicit driver changed: %v", got)
	}
	drivers[runtime.GOOS] = []string{vendor}
	if got := Drivers("opensc"); len(got) != 0 {
		t.Fatalf("vendor leaked into OpenSC mode: %v", got)
	}
}
