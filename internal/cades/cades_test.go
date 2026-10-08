package cades

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/bahricanli/eyazisma-imza/internal/testpki"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

var content = []byte(`<?xml version="1.0" encoding="UTF-8"?><PaketOzeti Id="4F9E2E9B-F4E6-4428-8F99-2E0A0D1D42D9"/>`)

// The signatures are read back and verified with another CMS implementation.
func TestSignatureVerifiesAndBindsTheCertificate(t *testing.T) {
	for name, elliptical := range map[string]bool{"RSA": false, "ECDSA": true} {
		t.Run(name, func(t *testing.T) {
			certificate, key := testpki.Certificate(t, "Ayşe Yılmaz", elliptical)

			signature, err := Sign(content, certificate, key, Options{})
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := pkcs7.Parse(signature)
			if err != nil {
				t.Fatalf("imza çözümlenemedi: %v", err)
			}

			if err := parsed.Verify(); err != nil {
				t.Fatalf("imza doğrulanamadı: %v", err)
			}

			if !bytes.Equal(parsed.Content, content) {
				t.Fatal("imza içeriği kendi içinde taşımıyor")
			}

			if signer := parsed.GetOnlySigner(); signer == nil || !signer.Equal(certificate) {
				t.Fatal("imzalayan sertifika imzada yok")
			}

			// CAdES-BES: the signing-certificate-v2 attribute carries the hash of the signer's certificate.
			var binding signingCertificateV2
			if err := parsed.UnmarshalSignedAttribute(oidSigningCertificateV2, &binding); err != nil {
				t.Fatalf("signing-certificate-v2 özniteliği yok: %v", err)
			}

			digest := sha256.Sum256(certificate.Raw)
			if len(binding.Certificates) != 1 || !bytes.Equal(binding.Certificates[0].Hash, digest[:]) || binding.Certificates[0].IssuerSerial.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
				t.Fatal("signing-certificate-v2 imzalayan sertifikayı göstermiyor")
			}

			if len(parsed.Signers[0].UnauthenticatedAttributes) != 0 {
				t.Fatal("zaman damgası istenmediği hâlde imzasız öznitelik var")
			}
		})
	}
}

func TestSignedAttributesAreInDerOrder(t *testing.T) {
	certificate, key := testpki.Certificate(t, "Ayşe Yılmaz", false)

	attributes, err := signedAttributes(content, certificate, Options{}.Time)
	if err != nil {
		t.Fatal(err)
	}

	var previous []byte
	rest := attributes

	for len(rest) > 0 {
		var raw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			t.Fatal(err)
		}

		if previous != nil && bytes.Compare(previous, raw.FullBytes) >= 0 {
			t.Fatal("imzalı öznitelikler DER sırasında değil")
		}

		previous = raw.FullBytes
	}

	_ = key
}

func TestTimestampIsOverTheSignatureValue(t *testing.T) {
	certificate, key := testpki.Certificate(t, "Ayşe Yılmaz", false)
	service := testpki.TimestampService(t, "1234", "gizli")

	signature, err := Sign(content, certificate, key, Options{Timestamper: HTTPTimestamper{URL: service.URL, User: "1234", Password: "gizli"}})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := pkcs7.Parse(signature)
	if err != nil {
		t.Fatal(err)
	}

	if err := parsed.Verify(); err != nil {
		t.Fatalf("zaman damgalı imza doğrulanamadı: %v", err)
	}

	unsigned := parsed.Signers[0].UnauthenticatedAttributes
	if len(unsigned) != 1 || !unsigned[0].Type.Equal(oidSignatureTimeStamp) {
		t.Fatalf("imza zaman damgası özniteliği yok: %v", unsigned)
	}

	token, err := timestamp.Parse(unsigned[0].Value.Bytes)
	if err != nil {
		t.Fatalf("zaman damgası çözümlenemedi: %v", err)
	}

	digest := sha256.Sum256(parsed.Signers[0].EncryptedDigest)
	if !bytes.Equal(token.HashedMessage, digest[:]) {
		t.Fatal("zaman damgası imza değerinin üzerine alınmamış")
	}
}

func TestSignatureIsNotReturnedWithoutTheTimestamp(t *testing.T) {
	certificate, key := testpki.Certificate(t, "Ayşe Yılmaz", false)
	service := testpki.TimestampService(t, "1234", "gizli")

	if _, err := Sign(content, certificate, key, Options{Timestamper: HTTPTimestamper{URL: service.URL, User: "1234", Password: "yanlis"}}); err == nil {
		t.Fatal("zaman damgası reddedildiği hâlde imza döndü")
	}

	if _, err := Sign(content, certificate, key, Options{Timestamper: wrongTimestamper{}}); err == nil {
		t.Fatal("hatalı zaman damgası kabul edildi")
	}
}

type wrongTimestamper struct{}

func (wrongTimestamper) Timestamp([]byte) ([]byte, error) { return nil, errors.New("hata") }
