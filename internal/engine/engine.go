// Package engine makes the signatures. The bridge only depends on the Engine
// interface, so the library behind it can be replaced.
package engine

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// Profile is the long-term signature profile asked for.
type Profile string

const (
	// ProfileBES is a plain signature without a time stamp.
	ProfileBES Profile = "BES"
	// ProfileXL is CAdES-X Long, asked for electronic signatures.
	ProfileXL Profile = "XL"
	// ProfileA is CAdES-A, asked for electronic seals.
	ProfileA Profile = "A"
)

// Timestamp is the time-stamp service used to reach a long-term profile.
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

// ErrNoTimestamp is returned when a long-term profile is asked for without a time-stamp service.
var ErrNoTimestamp = errors.New("uzun dönemli imza için zaman damgası hizmeti tanımlı değil")

// Engine opens keys and signs content.
type Engine interface {
	// OpenCard opens the signing key on the smart card or token with the PIN.
	OpenCard(pin string) (*Key, error)
	// OpenPFX opens a key from a PKCS#12 file; meant for testing.
	OpenPFX(data []byte, password string) (*Key, error)
	// Sign returns a CAdES signature that carries the content inside it,
	// upgraded to the profile when a time-stamp service is given.
	Sign(content []byte, key *Key, profile Profile, timestamp *Timestamp) ([]byte, error)
}
