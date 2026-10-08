// Package engine opens signing keys and makes the signatures. The bridge
// depends only on the Engine interface.
package engine

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/bahricanli/eyazisma-imza/internal/cades"
	"github.com/bahricanli/eyazisma-imza/internal/token"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Profile is a signature level.
type Profile string

const (
	// ProfileBES is a plain CAdES signature without a time stamp.
	ProfileBES Profile = "BES"
	// ProfileT carries a time stamp over the signature.
	ProfileT Profile = "T"
	// ProfileXL is CAdES-X Long, asked for electronic signatures.
	ProfileXL Profile = "XL"
	// ProfileA is CAdES-A, asked for electronic seals.
	ProfileA Profile = "A"
)

// Timestamp is the time-stamp service used above level BES.
type Timestamp struct {
	URL      string
	User     string
	Password string
}

// Key is an opened signing key with its certificate.
type Key struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	// Close releases the key (logs out of the card).
	Close func()
}

// Engine opens keys and signs content.
type Engine interface {
	// OpenCard opens the signing key on the smart card or token with the PIN.
	OpenCard(pin string) (*Key, error)
	// OpenPFX opens a key from a PKCS#12 file; meant for testing.
	OpenPFX(data []byte, password string) (*Key, error)
	// Sign returns a CAdES signature that carries the content inside it and
	// the level it reached: the highest one supported up to the level asked for.
	Sign(content []byte, key *Key, profile Profile, timestamp *Timestamp) ([]byte, Profile, error)
}

// Native signs with the bridge's own CAdES code and the card's PKCS#11 driver.
type Native struct {
	// Driver is the PKCS#11 driver to use; the usual ones are tried when empty.
	Driver string
}

func (e Native) OpenCard(pin string) (*Key, error) {
	if pin == "" {
		return nil, errors.New("PIN gerekli")
	}

	card, err := token.Open(e.Driver, pin)
	if err != nil {
		return nil, err
	}

	return &Key{Certificate: card.Certificate, Signer: card, Close: card.Close}, nil
}

func (Native) OpenPFX(data []byte, password string) (*Key, error) {
	key, certificate, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, errors.New("PFX dosyası açılamadı; parola yanlış olabilir")
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("PFX dosyasındaki anahtar imzalamayı desteklemiyor")
	}

	return &Key{Certificate: certificate, Signer: signer, Close: func() {}}, nil
}

// Sign reaches level T at most: the long-term levels are not built yet.
func (Native) Sign(content []byte, key *Key, profile Profile, timestamp *Timestamp) ([]byte, Profile, error) {
	options := cades.Options{}
	reached := ProfileBES

	if profile != ProfileBES && profile != "" && timestamp != nil && timestamp.URL != "" {
		options.Timestamper = cades.HTTPTimestamper{URL: timestamp.URL, User: timestamp.User, Password: timestamp.Password}
		reached = ProfileT
	}

	signature, err := cades.Sign(content, key.Certificate, key.Signer, options)
	if err != nil {
		return nil, "", err
	}

	return signature, reached, nil
}
