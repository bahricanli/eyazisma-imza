package engine

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strconv"

	"github.com/kilimcininkoroglu/eimza-go/cades"
	ecrypto "github.com/kilimcininkoroglu/eimza-go/crypto"
	"github.com/kilimcininkoroglu/eimza-go/crypto/alg"
	"github.com/kilimcininkoroglu/eimza-go/smartcard"
)

// Eimza signs with the eimza-go library.
type Eimza struct{}

func (Eimza) OpenCard(pin string) (*Key, error) {
	if pin == "" {
		return nil, errors.New("PIN gerekli")
	}

	result, err := smartcard.QuickOpen(pin, nil)
	if err != nil {
		return nil, fmt.Errorf("akıllı kart açılamadı: %w", err)
	}

	return &Key{Certificate: result.Certificate, Signer: result.Signer, Close: func() { _ = result.Close() }}, nil
}

func (Eimza) OpenPFX(data []byte, password string) (*Key, error) {
	content, err := ecrypto.ParsePfx(data, password)
	if err != nil {
		return nil, fmt.Errorf("PFX dosyası açılamadı: %w", err)
	}

	signer, ok := content.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("PFX dosyasındaki anahtar imzalamayı desteklemiyor")
	}

	return &Key{Certificate: content.Certificate, Signer: signer, Close: func() {}}, nil
}

func (Eimza) Sign(content []byte, key *Key, profile Profile, timestamp *Timestamp) ([]byte, error) {
	signed := cades.NewSignedData()
	// Attached: the content travels inside the signature, as the e-Yazışma guide asks.
	signed.AddContent(cades.SignableBytes(content))
	signed.AddSigner(cades.TypeBES, key.Certificate, key.Signer, algorithm(key), cades.DefaultSignParams())

	signature, err := signed.Sign()
	if err != nil {
		return nil, fmt.Errorf("imza atılamadı: %w", err)
	}

	if profile == ProfileBES || profile == "" {
		return signature, nil
	}

	if timestamp == nil || timestamp.URL == "" {
		return nil, ErrNoTimestamp
	}

	target, err := target(profile)
	if err != nil {
		return nil, err
	}

	options := &cades.UpgradeOpts{TSServerURL: timestamp.URL, TSHashAlg: "SHA-256", TSPassword: timestamp.Password}

	if timestamp.User != "" {
		// The library takes the account of the time-stamp service as a customer number.
		options.TSUserID, err = strconv.Atoi(timestamp.User)
		if err != nil {
			return nil, fmt.Errorf("zaman damgası kullanıcısı sayı olmalıdır: %q", timestamp.User)
		}
	}

	upgraded, err := cades.UpgradeSigner(signature, 0, target, options)
	if err != nil {
		return nil, fmt.Errorf("imza %s profiline yükseltilemedi: %w", profile, err)
	}

	return upgraded, nil
}

func algorithm(key *Key) alg.SignatureAlg {
	if _, ok := key.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
		return alg.ECDSA_SHA256
	}

	return alg.RSA_SHA256
}

func target(profile Profile) (cades.SignatureType, error) {
	switch profile {
	case ProfileXL:
		return cades.TypeXL, nil
	case ProfileA:
		return cades.TypeA, nil
	}

	return cades.TypeBES, fmt.Errorf("bilinmeyen imza profili: %s", profile)
}
