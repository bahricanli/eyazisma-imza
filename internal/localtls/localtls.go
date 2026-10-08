// Package localtls gives the bridge an HTTPS address on this computer, so a
// portal page served over HTTPS can reach it in every browser.
//
// The certificate is made on the computer it is used on, never shipped with
// the program: a shared key would be known to everyone who has the program,
// and trusting it would let any of them pose as a trusted site. The
// certificate here names only this computer's loopback addresses, cannot
// sign other certificates, and its key never leaves the computer.
package localtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Name of the certificate, as the system's certificate store shows it.
const Name = "eyazisma-imza (bu bilgisayar)"

// Systems refuse server certificates that last longer than about two years.
const lifetime = 800 * 24 * time.Hour

// Paths of the certificate and its key in the directory.
func Paths(directory string) (certificate, key string) {
	return filepath.Join(directory, "https-cert.pem"), filepath.Join(directory, "https-key.pem")
}

// Generate makes a new key and certificate for this computer's loopback addresses.
func Generate(directory string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: Name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}

	certificatePath, keyPath := Paths(directory)

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0o600); err != nil {
		return err
	}

	return os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o644)
}

// Load reads the certificate of this computer; it fails when there is none or it has expired.
func Load(directory string) (*tls.Certificate, error) {
	certificatePath, keyPath := Paths(directory)

	pair, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}

	if time.Now().After(leaf.NotAfter) {
		return nil, errors.New("bu bilgisayarın HTTPS sertifikasının süresi dolmuş; --https ile yenileyin")
	}

	pair.Leaf = leaf

	return &pair, nil
}

// Trust asks the system to accept the certificate for this user's browsers.
// The system may ask the user to confirm.
func Trust(directory string) error {
	certificate, _ := Paths(directory)

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		return run("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"), certificate)
	case "windows":
		return run("certutil", "-user", "-addstore", "Root", certificate)
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		database := filepath.Join(home, ".pki", "nssdb")
		if err := os.MkdirAll(database, 0o700); err != nil {
			return err
		}

		if _, err := exec.LookPath("certutil"); err != nil {
			return errors.New("certutil bulunamadı; tarayıcının sertifikayı tanıması için libnss3-tools (ya da nss-tools) paketini kurup yeniden deneyin")
		}

		return run("certutil", "-d", "sql:"+database, "-A", "-t", "P,,", "-n", Name, "-i", certificate)
	}
}

// Remove takes the certificate out of the system's trust and deletes it with its key.
func Remove(directory string) error {
	certificate, key := Paths(directory)

	if _, err := os.Stat(certificate); err == nil {
		switch runtime.GOOS {
		case "darwin":
			_ = exec.Command("security", "remove-trusted-cert", certificate).Run()
			_ = exec.Command("security", "delete-certificate", "-c", Name).Run()
		case "windows":
			_ = exec.Command("certutil", "-user", "-delstore", "Root", Name).Run()
		default:
			if home, err := os.UserHomeDir(); err == nil {
				_ = exec.Command("certutil", "-d", "sql:"+filepath.Join(home, ".pki", "nssdb"), "-D", "-n", Name).Run()
			}
		}
	}

	for _, path := range []string{certificate, key} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

func run(name string, arguments ...string) error {
	output, err := exec.Command(name, arguments...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", name, strings.TrimSpace(string(output)))
	}

	return nil
}
