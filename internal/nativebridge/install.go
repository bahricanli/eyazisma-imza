package nativebridge

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
)

type Settings struct {
	Driver   string `json:"driver,omitempty"`
	Port     int    `json:"port"`
	ChromeID string `json:"chrome_id"`
}

func settingsPath() (string, error) {
	directory, err := os.UserConfigDir()
	return filepath.Join(directory, "eyazisma-imza", "browser-host.json"), err
}
func LoadSettings() (Settings, error) {
	s := Settings{Port: 51515, ChromeID: ChromeID}
	path, err := settingsPath()
	if err != nil {
		return s, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	if s.Port < 1024 || s.Port > 65534 {
		return s, fmt.Errorf("geçersiz uygulama portu")
	}
	return s, err
}
func Install(executable string, settings Settings) error {
	if !regexp.MustCompile(`^[a-p]{32}$`).MatchString(settings.ChromeID) {
		return fmt.Errorf("Chrome eklenti kimliği geçersiz")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path, err := settingsPath()
	if err != nil {
		return err
	}
	if err := writeJSON(path, settings); err != nil {
		return err
	}
	chrome := map[string]any{"name": HostName, "description": "e-Yazışma yerel imza uygulaması", "path": executable, "type": "stdio", "allowed_origins": []string{"chrome-extension://" + settings.ChromeID + "/"}}
	firefox := map[string]any{"name": HostName, "description": "e-Yazışma yerel imza uygulaması", "path": executable, "type": "stdio", "allowed_extensions": []string{FirefoxID}}
	var chromePaths, firefoxPaths []string
	switch runtime.GOOS {
	case "darwin":
		chromePaths = []string{filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", HostName+".json")}
		firefoxPaths = []string{filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts", HostName+".json")}
	case "windows":
		directory := filepath.Dir(path)
		chromePaths = []string{filepath.Join(directory, "chrome-host.json")}
		firefoxPaths = []string{filepath.Join(directory, "firefox-host.json")}
	default:
		directory, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		chromePaths = []string{filepath.Join(directory, "google-chrome", "NativeMessagingHosts", HostName+".json"), filepath.Join(directory, "chromium", "NativeMessagingHosts", HostName+".json")}
		firefoxPaths = []string{filepath.Join(home, ".mozilla", "native-messaging-hosts", HostName+".json")}
	}
	for _, p := range chromePaths {
		if err := writeJSON(p, chrome); err != nil {
			return err
		}
	}
	for _, p := range firefoxPaths {
		if err := writeJSON(p, firefox); err != nil {
			return err
		}
	}
	if runtime.GOOS == "windows" {
		for key, p := range map[string]string{`HKCU\Software\Google\Chrome\NativeMessagingHosts\` + HostName: chromePaths[0], `HKCU\Software\Mozilla\NativeMessagingHosts\` + HostName: firefoxPaths[0]} {
			if err := exec.Command("reg", "add", key, "/ve", "/t", "REG_SZ", "/d", p, "/f").Run(); err != nil {
				return err
			}
		}
	}
	return nil
}
func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Called recognizes only invocations made by the registered browser manifests.
func Called(arguments []string, chromeID string) bool {
	if len(arguments) > 0 && arguments[0] == "chrome-extension://"+chromeID+"/" {
		return true
	}
	if len(arguments) == 2 && filepath.IsAbs(arguments[0]) && filepath.Ext(arguments[0]) == ".json" && arguments[1] == FirefoxID {
		return true
	}
	return false
}
