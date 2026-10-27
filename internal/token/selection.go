package token

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"

	"github.com/miekg/pkcs11"
)

// Selection binds a choice to a driver, physical token and certificate.
// It is made from a PIN-free scan, never from an arbitrary browser path.
type Selection struct {
	Driver      string
	Slot        uint
	Serial      string
	Fingerprint string
}

func Fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func OpenSelected(choice Selection, pin string) (*Token, error) {
	if pin == "" {
		return nil, errors.New("PIN gerekli")
	}
	runtime.LockOSThread()
	card, err := openSelected(choice, pin)
	if err != nil {
		runtime.UnlockOSThread()
	}
	return card, err
}

func openSelected(choice Selection, pin string) (*Token, error) {
	context := pkcs11.New(choice.Driver)
	if context == nil {
		return nil, errors.New("seçilen kartın sürücüsü yüklenemedi")
	}
	if err := initialize(context, choice.Driver); err != nil {
		context.Destroy()
		return nil, fmt.Errorf("seçilen kartın sürücüsü başlatılamadı: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = context.Finalize()
			context.Destroy()
		}
	}()
	info, err := context.GetTokenInfo(choice.Slot)
	if err != nil || clean(info.SerialNumber) != choice.Serial || info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
		return nil, errors.New("seçilen kart çıkarılmış veya değiştirilmiş; kartları yeniden listeleyin")
	}
	session, err := context.OpenSession(choice.Slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("seçilen kart açılamadı: %w", err)
	}
	loggedIn := false
	defer func() {
		if !success {
			if loggedIn {
				_ = context.Logout(session)
			}
			_ = context.CloseSession(session)
		}
	}()
	certificate, id := selectedCertificate(context, session, choice.Fingerprint)
	// A known certificate must still be on this card before any PIN attempt.
	if choice.Fingerprint != "" && certificate == nil {
		return nil, errors.New("seçilen sertifika kartta bulunamadı; kartları yeniden listeleyin")
	}
	if err := context.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, loginError(err)
	}
	loggedIn = true
	if certificate == nil {
		certificate, id = selectedCertificate(context, session, choice.Fingerprint)
	}
	if certificate == nil {
		return nil, errors.New("seçilen kartta imza sertifikası bulunamadı")
	}
	keys, err := objects(context, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil || len(keys) == 0 {
		return nil, errors.New("seçilen sertifikanın özel anahtarı kartta bulunamadı")
	}
	success = true
	return &Token{Certificate: certificate, context: context, session: session, key: keys[0]}, nil
}

func selectedCertificate(context *pkcs11.Ctx, session pkcs11.SessionHandle, fingerprint string) (*x509.Certificate, []byte) {
	if fingerprint == "" {
		return signingCertificate(context, session)
	}
	handles, err := objects(context, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	})
	if err != nil {
		return nil, nil
	}
	for _, handle := range handles {
		attributes, err := context.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil), pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil || len(attributes) != 2 {
			continue
		}
		certificate, err := x509.ParseCertificate(attributes[0].Value)
		if err == nil && !certificate.IsCA && Fingerprint(certificate) == fingerprint {
			return certificate, attributes[1].Value
		}
	}
	return nil, nil
}
