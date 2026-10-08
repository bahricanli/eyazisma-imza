package token

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/bahricanli/eyazisma-imza/internal/cades"
	"github.com/digitorus/pkcs7"
)

// Runs against a real PKCS#11 driver: scripts/softhsm-test.sh prepares a
// software token and sets the variables. Skipped otherwise.
func TestSigningWithATokenThroughItsDriver(t *testing.T) {
	driver, pin := os.Getenv("EYAZISMA_IMZA_TEST_PKCS11"), os.Getenv("EYAZISMA_IMZA_TEST_PIN")
	if driver == "" {
		t.Skip("EYAZISMA_IMZA_TEST_PKCS11 tanımlı değil")
	}

	if _, err := Open(driver, pin+"0"); err == nil || !strings.Contains(err.Error(), "PIN yanlış") {
		t.Fatalf("yanlış PIN: %v", err)
	}

	card, err := Open(driver, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()

	if want := os.Getenv("EYAZISMA_IMZA_TEST_NAME"); card.Certificate.Subject.CommonName != want {
		t.Fatalf("seçilen sertifika %q, beklenen %q", card.Certificate.Subject.CommonName, want)
	}

	content := []byte("<PaketOzeti/>")

	signature, err := cades.Sign(content, card.Certificate, card, cades.Options{})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := pkcs7.Parse(signature)
	if err != nil {
		t.Fatal(err)
	}

	if err := parsed.Verify(); err != nil {
		t.Fatalf("kartla atılan imza doğrulanamadı: %v", err)
	}

	if !bytes.Equal(parsed.Content, content) {
		t.Fatal("imza içeriği taşımıyor")
	}
}

func TestMissingDriverIsReported(t *testing.T) {
	if len(Drivers("")) != 0 {
		t.Skip("bu bilgisayarda bir sürücü kurulu")
	}

	if _, err := Open("/yok/surucu.so", "1234"); err == nil || !strings.Contains(err.Error(), "sürücüsü") {
		t.Fatalf("eksik sürücü: %v", err)
	}
}
