package autostart

import (
	"strings"
	"testing"
)

func TestLaunchAgentRunsTheBridgeWithItsArguments(t *testing.T) {
	job := LaunchAgent("/Applications/e-Yazışma & İmza/eyazisma-imza", []string{"--no-browser", "--pkcs11", "/usr/local/lib/libakisp11.dylib"})

	for _, want := range []string{
		"<string>" + label + "</string>",
		"<string>/Applications/e-Yazışma &amp; İmza/eyazisma-imza</string>",
		"<string>--no-browser</string>",
		"<string>/usr/local/lib/libakisp11.dylib</string>",
		"<key>RunAtLoad</key>",
	} {
		if !strings.Contains(job, want) {
			t.Errorf("launchd işinde yok: %s", want)
		}
	}
}

func TestDesktopEntryStartsTheBridge(t *testing.T) {
	entry := DesktopEntry("/opt/eyazisma imza/eyazisma-imza", []string{"--no-browser"})

	if !strings.Contains(entry, `Exec="/opt/eyazisma imza/eyazisma-imza" --no-browser`) || !strings.Contains(entry, "Terminal=false") {
		t.Fatalf("masaüstü girdisi: %s", entry)
	}
}
