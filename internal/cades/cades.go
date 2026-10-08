// Package cades builds CAdES signatures (ETSI TS 101 733) as CMS SignedData
// (RFC 5652) that carry the signed content inside them.
//
// Levels: BES, with the signing-certificate-v2 attribute that binds the
// signature to the signer's certificate, and T, which adds a time stamp over
// the signature value. The long-term levels (X Long, A) are not built yet.
package cades

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

var (
	oidData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSignatureTimeStamp   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// Timestamper returns an RFC 3161 time-stamp token over a signature value.
type Timestamper interface {
	Timestamp(signature []byte) ([]byte, error)
}

// Options of a signature.
type Options struct {
	// Chain holds the certificates of the issuers, put in the signature next to the signer's.
	Chain []*x509.Certificate
	// Timestamper, when set, raises the signature to level T.
	Timestamper Timestamper
	// Time is the claimed signing time; now when zero.
	Time time.Time
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulatedContentInfo
	// [0] IMPLICIT SET OF Certificate, built by hand.
	Certificates asn1.RawValue
	SignerInfos  []signerInfo `asn1:"set"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,tag:0"`
}

type signerInfo struct {
	Version          int
	SignerIdentifier issuerAndSerialNumber
	DigestAlgorithm  pkix.AlgorithmIdentifier
	// [0] IMPLICIT SET OF Attribute, built by hand.
	SignedAttributes   asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	// [1] IMPLICIT SET OF Attribute, built by hand.
	UnsignedAttributes asn1.RawValue `asn1:"optional"`
}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// signing-certificate-v2 (RFC 5035). The hash algorithm is left out: SHA-256 is its default.
type signingCertificateV2 struct {
	Certificates []essCertIDv2
}

type essCertIDv2 struct {
	Hash         []byte
	IssuerSerial issuerSerial
}

type issuerSerial struct {
	Issuer       []asn1.RawValue
	SerialNumber *big.Int
}

// Sign signs the content with the key of the certificate and returns the
// DER-encoded signature. The signer gets the SHA-256 digest of the signed
// attributes, as a smart card expects.
func Sign(content []byte, certificate *x509.Certificate, signer crypto.Signer, options Options) ([]byte, error) {
	if certificate == nil || signer == nil {
		return nil, errors.New("cades: sertifika ve anahtar gerekli")
	}

	signatureAlgorithm, err := signatureAlgorithmOf(certificate)
	if err != nil {
		return nil, err
	}

	signingTime := options.Time
	if signingTime.IsZero() {
		signingTime = time.Now()
	}

	signedAttributes, err := signedAttributes(content, certificate, signingTime)
	if err != nil {
		return nil, err
	}

	// The signature covers the attributes encoded as a SET OF; in the
	// signature they appear under the implicit tag [0] with the same content.
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signedAttributes})
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(set)

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cades: imza atılamadı: %w", err)
	}

	info := signerInfo{
		Version:            1,
		SignerIdentifier:   issuerAndSerialNumber{Issuer: asn1.RawValue{FullBytes: certificate.RawIssuer}, SerialNumber: certificate.SerialNumber},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SignedAttributes:   asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedAttributes},
		SignatureAlgorithm: signatureAlgorithm,
		Signature:          signature,
	}

	if options.Timestamper != nil {
		token, err := options.Timestamper.Timestamp(signature)
		if err != nil {
			return nil, fmt.Errorf("cades: zaman damgası alınamadı: %w", err)
		}

		unsigned, err := encodeAttributes([]attribute{{Type: oidSignatureTimeStamp, Values: []asn1.RawValue{{FullBytes: token}}}})
		if err != nil {
			return nil, err
		}

		info.UnsignedAttributes = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: unsigned}
	}

	var certificates []byte
	for _, each := range append([]*x509.Certificate{certificate}, options.Chain...) {
		certificates = append(certificates, each.Raw...)
	}

	data, err := asn1.Marshal(signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: encapsulatedContentInfo{ContentType: oidData, Content: content},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certificates},
		SignerInfos:      []signerInfo{info},
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: data}})
}

// signedAttributes returns the content of the SET OF signed attributes.
func signedAttributes(content []byte, certificate *x509.Certificate, signingTime time.Time) ([]byte, error) {
	contentType, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}

	contentDigest := sha256.Sum256(content)
	messageDigest, err := asn1.Marshal(contentDigest[:])
	if err != nil {
		return nil, err
	}

	encodedTime, err := asn1.Marshal(signingTime.UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}

	certificateDigest := sha256.Sum256(certificate.Raw)
	signingCertificate, err := asn1.Marshal(signingCertificateV2{Certificates: []essCertIDv2{{
		Hash: certificateDigest[:],
		IssuerSerial: issuerSerial{
			// GeneralName directoryName [4], explicit because Name is a CHOICE.
			Issuer:       []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: certificate.RawIssuer}},
			SerialNumber: certificate.SerialNumber,
		},
	}}})
	if err != nil {
		return nil, err
	}

	return encodeAttributes([]attribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: contentType}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: messageDigest}}},
		{Type: oidSigningTime, Values: []asn1.RawValue{{FullBytes: encodedTime}}},
		{Type: oidSigningCertificateV2, Values: []asn1.RawValue{{FullBytes: signingCertificate}}},
	})
}

// encodeAttributes returns the attributes encoded one after the other in the
// order DER asks of a SET OF: sorted by their encodings.
func encodeAttributes(attributes []attribute) ([]byte, error) {
	encoded := make([][]byte, 0, len(attributes))

	for _, each := range attributes {
		der, err := asn1.Marshal(each)
		if err != nil {
			return nil, err
		}

		encoded = append(encoded, der)
	}

	sort.Slice(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })

	return bytes.Join(encoded, nil), nil
}

func signatureAlgorithmOf(certificate *x509.Certificate) (pkix.AlgorithmIdentifier, error) {
	switch certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, nil
	}

	return pkix.AlgorithmIdentifier{}, errors.New("cades: sertifikanın anahtar türü desteklenmiyor (RSA ya da ECDSA olmalı)")
}
