package localtls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestCertificateServesOnlyThisComputer(t *testing.T) {
	directory := t.TempDir()

	if _, err := Load(directory); err == nil {
		t.Fatal("sertifika yokken yüklendi")
	}

	if err := Generate(directory); err != nil {
		t.Fatal(err)
	}

	pair, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}

	leaf := pair.Leaf
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("sertifika başka sertifika imzalayabiliyor")
	}

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" || len(leaf.IPAddresses) != 2 || !leaf.IPAddresses[0].IsLoopback() || !leaf.IPAddresses[1].IsLoopback() {
		t.Fatalf("sertifika bu bilgisayar dışında adres içeriyor: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}

	if leaf.NotAfter.Sub(leaf.NotBefore) > 825*24*time.Hour {
		t.Fatal("sertifika sistemlerin kabul ettiğinden uzun süreli")
	}

	// Windows keeps the file to its owner through the profile folder's access list, not through mode bits.
	_, keyPath := Paths(directory)
	if info, err := os.Stat(keyPath); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("anahtar dosyası yalnız sahibine açık olmalı: %v %v", info, err)
	}

	// A browser that trusts the certificate reaches the bridge over HTTPS at 127.0.0.1.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "tamam") }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*pair}}
	server.StartTLS()
	defer server.Close()

	trusted := x509.NewCertPool()
	trusted.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trusted}}}

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("güvenilen sertifikayla bağlanılamadı: %v", err)
	}
	response.Body.Close()

	// Each computer gets its own key.
	other := t.TempDir()
	if err := Generate(other); err != nil {
		t.Fatal(err)
	}
	second, _ := Load(other)
	if second.Leaf.Equal(leaf) {
		t.Fatal("iki bilgisayar aynı sertifikayı aldı")
	}
}
