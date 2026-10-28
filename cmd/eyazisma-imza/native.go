package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/bahricanli/eyazisma-imza/internal/nativebridge"
)

func nativeHost() error {
	settings, err := nativebridge.LoadSettings()
	if err != nil {
		return err
	}
	return nativebridge.Serve(os.Stdin, os.Stdout, version, func(link string) error {
		address := fmt.Sprintf("http://127.0.0.1:%d", settings.Port)
		if !bridgeReady(address) {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			arguments := []string{"--no-browser", "--port", fmt.Sprint(settings.Port)}
			if settings.Driver != "" {
				arguments = append(arguments, "--pkcs11", settings.Driver)
			}
			command := exec.Command(executable, arguments...)
			// Never inherit the native-messaging stdout pipe in a background bridge.
			if err := command.Start(); err != nil {
				return fmt.Errorf("imza uygulaması başlatılamadı")
			}
			go func() { _ = command.Wait() }()
			deadline := time.Now().Add(6 * time.Second)
			for !bridgeReady(address) {
				if time.Now().After(deadline) {
					return fmt.Errorf("imza uygulaması açılamadı; port veya kurulum ayarlarını kontrol edin")
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		if link == "" {
			openBrowser(address + "/cards")
		} else {
			openBrowser(address + "/?link=" + url.QueryEscape(link))
		}
		return nil
	})
}
func bridgeReady(address string) bool {
	client := &http.Client{Timeout: 400 * time.Millisecond, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(address + "/status")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var status struct {
		Name string `json:"name"`
	}
	return response.StatusCode == 200 && json.NewDecoder(response.Body).Decode(&status) == nil && status.Name == "eyazisma-imza"
}
