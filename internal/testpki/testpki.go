// Package testpki makes throwaway certificates and a time-stamp service for tests.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// Certificate returns a self-signed signing certificate with its key; ECDSA when asked, RSA otherwise.
func Certificate(t testing.TB, name string, elliptical bool, usages ...x509.ExtKeyUsage) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	var key crypto.Signer
	var err error

	if elliptical {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name, Country: []string{"TR"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:  usages,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate, key
}

// TimestampService is an RFC 3161 service that stamps whatever it is asked.
// When a user is given, it wants that user with HTTP basic authentication.
func TimestampService(t testing.TB, user, password string) *httptest.Server {
	t.Helper()

	certificate, key := Certificate(t, "Sınama Zaman Damgası", false, x509.ExtKeyUsageTimeStamping)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotUser, gotPassword, ok := r.BasicAuth(); user != "" && (!ok || gotUser != user || gotPassword != password) {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		body, _ := io.ReadAll(r.Body)
		query, err := timestamp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		response, err := (&timestamp.Timestamp{
			HashAlgorithm:     query.HashAlgorithm,
			HashedMessage:     query.HashedMessage,
			Time:              time.Now(),
			SerialNumber:      big.NewInt(time.Now().UnixNano()),
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
			AddTSACertificate: true,
		}).CreateResponse(certificate, key)
		if err != nil {
			t.Logf("zaman damgası üretilemedi: %v", err)
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)

	return server
}
