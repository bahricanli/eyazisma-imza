// Package autostart makes the bridge start with the user's session, so it
// runs in the background as a service and the portal finds it listening.
package autostart

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const name = "eyazisma-imza"

// label is the identifier of the service on macOS.
const label = "tr.org.lkd.eyazisma-imza"

// Install registers the program to start at login with the arguments and starts it now where the system allows.
func Install(executable string, arguments []string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		path, err := launchAgentPath()
		if err != nil {
			return "", err
		}

		if err := write(path, LaunchAgent(executable, arguments)); err != nil {
			return "", err
		}

		// Replace a running copy, then start the new one.
		_ = exec.Command("launchctl", "bootout", domain(), path).Run()
		if output, err := exec.Command("launchctl", "bootstrap", domain(), path).CombinedOutput(); err != nil {
			return path, fmt.Errorf("servis kaydedildi ama başlatılamadı: %s", strings.TrimSpace(string(output)))
		}

		return path, nil
	case "windows":
		command := `"` + executable + `"`
		if len(arguments) > 0 {
			command += " " + strings.Join(arguments, " ")
		}

		if output, err := exec.Command("reg", "add", runKey, "/v", name, "/t", "REG_SZ", "/d", command, "/f").CombinedOutput(); err != nil {
			return "", fmt.Errorf("başlangıç kaydı yazılamadı: %s", strings.TrimSpace(string(output)))
		}

		return runKey + `\` + name, nil
	default:
		path, err := desktopEntryPath()
		if err != nil {
			return "", err
		}

		return path, write(path, DesktopEntry(executable, arguments))
	}
}

// Uninstall removes the registration and stops the service where the system runs it.
func Uninstall() error {
	switch runtime.GOOS {
	case "darwin":
		path, err := launchAgentPath()
		if err != nil {
			return err
		}

		_ = exec.Command("launchctl", "bootout", domain(), path).Run()

		return remove(path)
	case "windows":
		_ = exec.Command("reg", "delete", runKey, "/v", name, "/f").Run()

		return nil
	default:
		path, err := desktopEntryPath()
		if err != nil {
			return err
		}

		return remove(path)
	}
}

const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

// LaunchAgent is the launchd job that runs the bridge in the user's session on macOS.
func LaunchAgent(executable string, arguments []string) string {
	var items strings.Builder
	for _, argument := range append([]string{executable}, arguments...) {
		items.WriteString("\t\t<string>" + escape(argument) + "</string>\n")
	}

	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
` + items.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`
}

// DesktopEntry starts the bridge with the desktop session on Linux.
func DesktopEntry(executable string, arguments []string) string {
	command := `"` + executable + `"`
	if len(arguments) > 0 {
		command += " " + strings.Join(arguments, " ")
	}

	return "[Desktop Entry]\nType=Application\nName=e-Yazışma imza uygulaması\nExec=" + command + "\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
}

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

func desktopEntryPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, "autostart", name+".desktop"), nil
}

func domain() string {
	return fmt.Sprintf("gui/%d", os.Getuid())
}

func write(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

func remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func escape(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)
}
