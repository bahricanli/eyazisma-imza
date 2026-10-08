// Package token signs with the key on a smart card or USB token through the
// vendor's PKCS#11 driver. The private key never leaves the card.
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"

	"github.com/miekg/pkcs11"
)

// Drivers are the usual places of the PKCS#11 drivers of the cards used for e-signatures.
var drivers = map[string][]string{
	"windows": {
		`C:\Windows\System32\akisp11.dll`,
		`C:\Windows\System32\eTPKCS11.dll`,
		`C:\Windows\System32\aetpkss1.dll`,
		`C:\Windows\System32\OcsPkcs11Wrapper.dll`,
		`C:\Windows\System32\opensc-pkcs11.dll`,
	},
	"darwin": {
		"/usr/local/lib/libakisp11.dylib",
		"/usr/local/lib/libeTPkcs11.dylib",
		"/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
		"/usr/local/lib/libaetpkss.dylib",
		"/usr/local/lib/libOcsPkcs11Wrapper.dylib",
		"/Library/OpenSC/lib/opensc-pkcs11.so",
		"/opt/homebrew/lib/opensc-pkcs11.so",
		"/usr/local/lib/opensc-pkcs11.so",
	},
	"linux": {
		"/usr/lib/libakisp11.so",
		"/usr/local/lib/libakisp11.so",
		"/usr/lib/libeTPkcs11.so",
		"/usr/lib/libeToken.so",
		"/usr/lib/libaetpkss.so",
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
		"/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
		"/usr/lib64/opensc-pkcs11.so",
		"/usr/lib/opensc-pkcs11.so",
	},
}

// Token is an opened signing key on a card.
type Token struct {
	Certificate *x509.Certificate

	context *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
}

// Drivers lists the drivers present on this computer, the given one first.
func Drivers(preferred string) []string {
	var found []string

	for _, path := range append([]string{preferred}, drivers[runtime.GOOS]...) {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}

	return found
}

// Open finds a signing certificate on a card and logs in with the PIN.
// Only the card that holds the certificate sees the PIN, so a wrong PIN does
// not use up the tries of another card.
func Open(driver, pin string) (*Token, error) {
	found := Drivers(driver)
	if len(found) == 0 {
		return nil, errors.New("akıllı kart sürücüsü (PKCS#11) bulunamadı; sertifika sağlayıcınızın sürücüsünü kurun ya da yerini --pkcs11 ile gösterin")
	}

	var last error

	for _, path := range found {
		token, err := open(path, pin)
		if err == nil {
			return token, nil
		}

		last = err

		var pinError pinError
		if errors.As(err, &pinError) {
			return nil, err
		}
	}

	return nil, last
}

type pinError struct{ message string }

func (e pinError) Error() string { return e.message }

func open(path, pin string) (*Token, error) {
	context := pkcs11.New(path)
	if context == nil {
		return nil, fmt.Errorf("sürücü yüklenemedi: %s", path)
	}

	if err := context.Initialize(); err != nil {
		context.Destroy()

		return nil, fmt.Errorf("sürücü başlatılamadı (%s): %w", path, err)
	}

	token, err := find(context, pin)
	if err != nil {
		_ = context.Finalize()
		context.Destroy()

		return nil, err
	}

	return token, nil
}

func find(context *pkcs11.Ctx, pin string) (*Token, error) {
	present, err := context.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("kart okuyucuları listelenemedi: %w", err)
	}

	// A card that was never set up has nothing to sign with.
	var slots []uint
	for _, slot := range present {
		if info, err := context.GetTokenInfo(slot); err == nil && info.Flags&pkcs11.CKF_TOKEN_INITIALIZED != 0 {
			slots = append(slots, slot)
		}
	}

	for _, slot := range slots {
		session, err := context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			continue
		}

		// Most cards show their certificates without the PIN. One that does
		// not is logged in to only when it is the only card, so the PIN is
		// never tried on a card it may not belong to.
		certificate, id := signingCertificate(context, session)
		if certificate == nil && len(slots) > 1 {
			_ = context.CloseSession(session)

			continue
		}

		if err := context.Login(session, pkcs11.CKU_USER, pin); err != nil {
			_ = context.CloseSession(session)

			return nil, loginError(err)
		}

		if certificate == nil {
			certificate, id = signingCertificate(context, session)
		}

		if certificate == nil {
			_ = context.Logout(session)
			_ = context.CloseSession(session)

			continue
		}

		keys, err := objects(context, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		})
		if err != nil || len(keys) == 0 {
			_ = context.Logout(session)
			_ = context.CloseSession(session)

			return nil, errors.New("kartta sertifikanın özel anahtarı bulunamadı")
		}

		return &Token{Certificate: certificate, context: context, session: session, key: keys[0]}, nil
	}

	if len(slots) > 1 {
		return nil, errors.New("takılı kartlarda imza sertifikası bulunamadı; yalnız imza kartınızı takılı bırakıp yeniden deneyin")
	}

	return nil, errors.New("takılı bir kartta imza sertifikası bulunamadı")
}

// signingCertificate picks the certificate meant for signing documents:
// not a CA, and marked for non-repudiation when the card has such a one.
func signingCertificate(context *pkcs11.Ctx, session pkcs11.SessionHandle) (*x509.Certificate, []byte) {
	handles, err := objects(context, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	})
	if err != nil {
		return nil, nil
	}

	var chosen *x509.Certificate
	var chosenID []byte

	for _, handle := range handles {
		attributes, err := context.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attributes) != 2 {
			continue
		}

		certificate, err := x509.ParseCertificate(attributes[0].Value)
		if err != nil || certificate.IsCA {
			continue
		}

		nonRepudiation := certificate.KeyUsage&x509.KeyUsageContentCommitment != 0
		signs := nonRepudiation || certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0 || certificate.KeyUsage == 0

		if signs && (chosen == nil || (nonRepudiation && chosen.KeyUsage&x509.KeyUsageContentCommitment == 0)) {
			chosen, chosenID = certificate, attributes[1].Value
		}
	}

	return chosen, chosenID
}

func objects(context *pkcs11.Ctx, session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := context.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	defer context.FindObjectsFinal(session)

	handles, _, err := context.FindObjects(session, 32)

	return handles, err
}

func loginError(err error) error {
	var code pkcs11.Error
	if errors.As(err, &code) {
		switch code {
		case pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_INVALID, pkcs11.CKR_PIN_LEN_RANGE:
			return pinError{"PIN yanlış"}
		case pkcs11.CKR_PIN_LOCKED:
			return pinError{"PIN kilitlenmiş; kartın kilidini sertifika sağlayıcınızın aracıyla açın"}
		case pkcs11.CKR_PIN_EXPIRED:
			return pinError{"PIN'in süresi dolmuş"}
		}
	}

	return fmt.Errorf("karta giriş yapılamadı: %w", err)
}

func (t *Token) Public() crypto.PublicKey { return t.Certificate.PublicKey }

// DigestInfo prefix of SHA-256 for PKCS#1 v1.5 signatures (RFC 8017, 9.2).
var sha256Prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// Sign signs a SHA-256 digest on the card.
func (t *Token) Sign(_ io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	if options == nil || options.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("kart yalnız SHA-256 özetini imzalar")
	}

	switch t.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := t.context.SignInit(t.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, t.key); err != nil {
			return nil, err
		}

		return t.context.Sign(t.session, append(append([]byte{}, sha256Prefix...), digest...))
	case *ecdsa.PublicKey:
		if err := t.context.SignInit(t.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, t.key); err != nil {
			return nil, err
		}

		raw, err := t.context.Sign(t.session, digest)
		if err != nil {
			return nil, err
		}

		// The card returns r and s side by side; CMS wants them as an ASN.1 sequence.
		half := len(raw) / 2

		return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:])})
	}

	return nil, errors.New("karttaki anahtar türü desteklenmiyor")
}

// Close logs out of the card and unloads the driver.
func (t *Token) Close() {
	_ = t.context.Logout(t.session)
	_ = t.context.CloseSession(t.session)
	_ = t.context.Finalize()
	t.context.Destroy()
}
