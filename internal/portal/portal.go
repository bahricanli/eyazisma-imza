// Package portal talks to the portal that asked for a signature. The signing
// link is the only credential: single-use and short-lived.
package portal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Session is what the portal wants signed and how.
type Session struct {
	Organization string     `json:"organization"`
	DocumentNo   string     `json:"document_no"`
	Subject      string     `json:"subject"`
	Step         string     `json:"step"`
	StepLabel    string     `json:"step_label"`
	Filename     string     `json:"filename"`
	Content      string     `json:"content"`
	Profile      string     `json:"profile"`
	Timestamp    *Timestamp `json:"timestamp"`
	ExpiresAt    string     `json:"expires_at"`
}

// Timestamp is the time-stamp account the portal lends for this signature.
type Timestamp struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// Result is the portal's answer to a returned signature.
type Result struct {
	Message  string `json:"message"`
	Complete bool   `json:"complete"`
}

// Client fetches signing sessions and returns signatures.
type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Origin of a signing link (scheme and host), which the user must trust.
// Plain http is accepted only for a portal on this computer.
func Origin(link string) (string, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Host == "" {
		return "", errors.New("imza bağlantısı geçerli bir adres değil")
	}

	local := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"

	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && local) {
		return "", errors.New("imza bağlantısı https ile başlamalıdır")
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}

// Fetch asks the portal what is to be signed.
func (c *Client) Fetch(link string) (*Session, error) {
	request, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}

	session := &Session{}
	if err := c.do(request, session); err != nil {
		return nil, err
	}

	return session, nil
}

// Document decodes the content to sign.
func (s *Session) Document() ([]byte, error) {
	content, err := base64.StdEncoding.DecodeString(s.Content)
	if err != nil || len(content) == 0 {
		return nil, errors.New("portal imzalanacak içeriği göndermedi")
	}

	return content, nil
}

// Submit returns the signature; the link is spent when the portal accepts it.
func (c *Client) Submit(link string, signature []byte) (*Result, error) {
	body, _ := json.Marshal(map[string]string{"signature": base64.StdEncoding.EncodeToString(signature)})

	request, err := http.NewRequest(http.MethodPost, link, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	result := &Result{}
	if err := c.do(request, result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) do(request *http.Request, into any) error {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "eyazisma-imza")

	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("portala ulaşılamadı: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("portalın yanıtı okunamadı: %w", err)
	}

	if response.StatusCode >= 300 {
		var failure struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &failure) == nil && failure.Message != "" {
			return errors.New(failure.Message)
		}

		return fmt.Errorf("portal isteği kabul etmedi (%d)", response.StatusCode)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return errors.New("portalın yanıtı anlaşılamadı")
	}

	return nil
}
