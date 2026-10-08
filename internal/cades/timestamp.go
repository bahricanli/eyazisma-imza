package cades

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

// HTTPTimestamper asks an RFC 3161 time-stamp service over HTTP, with HTTP
// basic authentication when a user is given.
type HTTPTimestamper struct {
	URL      string
	User     string
	Password string
	Client   *http.Client
}

func (t HTTPTimestamper) Timestamp(signature []byte) ([]byte, error) {
	query, err := timestamp.CreateRequest(bytes.NewReader(signature), &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/timestamp-query")

	if t.User != "" {
		request.SetBasicAuth(t.User, t.Password)
	}

	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zaman damgası hizmeti isteği reddetti (%d)", response.StatusCode)
	}

	parsed, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, fmt.Errorf("zaman damgası yanıtı okunamadı: %w", err)
	}

	// The token must be over this signature and nothing else.
	digest := sha256.Sum256(signature)
	if parsed.HashAlgorithm != crypto.SHA256 || !bytes.Equal(parsed.HashedMessage, digest[:]) {
		return nil, errors.New("zaman damgası bu imzaya ait değil")
	}

	return parsed.RawToken, nil
}
