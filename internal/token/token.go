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
	"strings"

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

// Drivers lists the drivers to try: the given one alone, or else the usual
// ones present on this computer.
func Drivers(only string) []string {
	candidates := drivers[runtime.GOOS]
	if only != "" {
		candidates = []string{only}
	}

	var found []string

	for _, path := range candidates {
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

	// Card drivers expect to be called from one thread; the caller signs and
	// closes on the same goroutine, where Close lets the thread go.
	runtime.LockOSThread()

	var last error

	for _, path := range found {
		trace("yükleniyor: %s", path)
		token, err := open(path, pin)
		if err == nil {
			return token, nil
		}

		trace("açılamadı: %v", err)

		last = err

		// A driver that saw a card is the card's driver: its answer stands,
		// and another vendor's driver is not tried on the card.
		var pinError pinError
		if errors.As(err, &pinError) || errors.Is(err, errCardWithoutKey) {
			runtime.UnlockOSThread()

			return nil, err
		}
	}

	runtime.UnlockOSThread()

	return nil, last
}

// trace reports each step to the driver when EYAZISMA_IMZA_DEBUG is set, to
// find where a driver fails or crashes.
func trace(format string, arguments ...any) {
	if os.Getenv("EYAZISMA_IMZA_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[pkcs11] "+format+"\n", arguments...)
	}
}

// initialize starts a driver. Drivers disagree on the arguments: some refuse
// the locking flag the library sends by default, and AKİS wants no arguments
// at all, which the library cannot send, so the driver is called directly.
func initialize(context *pkcs11.Ctx, path string) error {
	trace("C_Initialize")
	err := context.Initialize()
	trace("C_Initialize: %v", err)

	if !isCode(err, pkcs11.CKR_ARGUMENTS_BAD) {
		return err
	}

	err = context.Initialize(pkcs11.InitializeWithFlags(0))
	trace("C_Initialize (bayraksız): %v", err)

	if !isCode(err, pkcs11.CKR_ARGUMENTS_BAD) {
		return err
	}

	result := initializeWithoutArguments(path)
	trace("C_Initialize (argümansız): %#x", result)

	if result != 0 && result != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
		return pkcs11.Error(result)
	}

	return nil
}

func isCode(err error, code uint) bool {
	var found pkcs11.Error

	return errors.As(err, &found) && uint(found) == code
}

// errCardWithoutKey marks the failures of a driver that did see a card.
var errCardWithoutKey = errors.New("kart görüldü")

func seen(message string) error { return fmt.Errorf("%s%w", message, hidden{errCardWithoutKey}) }

// hidden keeps a marker error out of the message.
type hidden struct{ error }

func (hidden) Error() string { return "" }

func clean(text string) string { return strings.Trim(text, "\x00 ") }

type pinError struct{ message string }

func (e pinError) Error() string { return e.message }

func open(path, pin string) (*Token, error) {
	context := pkcs11.New(path)
	if context == nil {
		return nil, fmt.Errorf("sürücü yüklenemedi: %s", path)
	}

	if err := initialize(context, path); err != nil {
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

			return nil, seen("kartta sertifikanın özel anahtarı bulunamadı")
		}

		return &Token{Certificate: certificate, context: context, session: session, key: keys[0]}, nil
	}

	if len(slots) > 1 {
		return nil, seen("takılı kartlarda imza sertifikası bulunamadı; yalnız imza kartınızı takılı bırakıp yeniden deneyin")
	}

	if len(slots) == 1 {
		return nil, seen("kartta imza sertifikası bulunamadı")
	}

	return nil, errors.New("takılı bir kart bulunamadı")
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
	runtime.UnlockOSThread()
}

// Card describes a card a driver sees, with the certificates it shows without the PIN.
type Card struct {
	Driver       string
	Label        string
	Model        string
	Certificates []*x509.Certificate
	// Chosen is the certificate that would sign; nil when none is visible before login.
	Chosen *x509.Certificate
}

// List reports the cards each driver sees. It never logs in, so no PIN is used.
func List(driver string) ([]Card, []error) {
	var cards []Card
	var problems []error

	// Card drivers expect to be called from one thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for _, path := range Drivers(driver) {
		trace("yükleniyor: %s", path)
		context := pkcs11.New(path)
		if context == nil {
			problems = append(problems, fmt.Errorf("sürücü yüklenemedi: %s", path))

			continue
		}

		if err := initialize(context, path); err != nil {
			context.Destroy()
			problems = append(problems, fmt.Errorf("sürücü başlatılamadı (%s): %w", path, err))

			continue
		}

		trace("C_GetSlotList")
		slots, err := context.GetSlotList(true)
		trace("C_GetSlotList: %v %v", slots, err)

		for _, slot := range slots {
			trace("C_GetTokenInfo(%d)", slot)
			info, err := context.GetTokenInfo(slot)
			trace("C_GetTokenInfo: %q bayraklar %#x %v", info.Label, info.Flags, err)

			if err != nil || info.Flags&pkcs11.CKF_TOKEN_INITIALIZED == 0 {
				continue
			}

			card := Card{Driver: path, Label: clean(info.Label), Model: clean(info.Model)}

			trace("C_OpenSession(%d)", slot)
			session, err := context.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
			trace("C_OpenSession: %v", err)

			if err == nil {
				trace("sertifikalar aranıyor")
				card.Certificates = certificates(context, session)
				trace("%d sertifika", len(card.Certificates))
				card.Chosen, _ = signingCertificate(context, session)
				trace("C_CloseSession")
				_ = context.CloseSession(session)
			}

			cards = append(cards, card)
		}

		trace("C_Finalize")
		_ = context.Finalize()
		trace("sürücü bırakılıyor")
		context.Destroy()
		trace("bitti: %s", path)

		// The card has its driver; another vendor's driver has no business with it.
		if len(cards) > 0 {
			break
		}
	}

	return cards, problems
}

func certificates(context *pkcs11.Ctx, session pkcs11.SessionHandle) []*x509.Certificate {
	handles, err := objects(context, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	})
	if err != nil {
		return nil
	}

	var found []*x509.Certificate

	for _, handle := range handles {
		attributes, err := context.GetAttributeValue(session, handle, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
		if err != nil || len(attributes) != 1 {
			continue
		}

		if certificate, err := x509.ParseCertificate(attributes[0].Value); err == nil {
			found = append(found, certificate)
		}
	}

	return found
}
