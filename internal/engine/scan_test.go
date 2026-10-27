package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func scanHelper(t *testing.T, source string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell helper is for Unix")
	}
	path := filepath.Join(t.TempDir(), "scanner")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+source+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAStuckDriverScanIsStoppedWithoutBlockingTheBridge(t *testing.T) {
	path := scanHelper(t, "exec sleep 10")
	start := time.Now()
	if _, err := scanDriver(path, "driver", 25*time.Millisecond); err == nil || !strings.Contains(err.Error(), "yanıt vermedi") {
		t.Fatalf("timeout: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("driver timeout blocked the bridge")
	}
}

func TestScannerRejectsCrashesAndMalformedResponses(t *testing.T) {
	for _, source := range []string{"exit 2", "printf 'not json'"} {
		if _, err := scanDriver(scanHelper(t, source), "driver", time.Second); err == nil {
			t.Fatal("bad driver response accepted")
		}
	}
	cards, err := scanDriver(scanHelper(t, `printf '%s' '{"cards":[{"Label":"Test card","Selection":{"Driver":"driver","Slot":2,"Serial":"test","Fingerprint":"test"}}]}'`), "driver", time.Second)
	if err != nil || len(cards) != 1 || cards[0].Selection.Slot != 2 {
		t.Fatalf("valid scan: %v %v", cards, err)
	}
}
