package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/bahricanli/eyazisma-imza/internal/config"
	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/portal"
	"github.com/bahricanli/eyazisma-imza/internal/testpki"
	"github.com/digitorus/pkcs7"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const digest = `<?xml version="1.0" encoding="UTF-8"?><PaketOzeti Id="4F9E2E9B-F4E6-4428-8F99-2E0A0D1D42D9"/>`

// fakePortal answers like the portal's signing endpoints and keeps what it was sent.
type fakePortal struct {
	lock      sync.Mutex
	timestamp map[string]string
	signature []byte
	fetched   int
}

func (p *fakePortal) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /imza/{token}", func(w http.ResponseWriter, r *http.Request) {
		p.lock.Lock()
		p.fetched++
		spent := p.signature != nil
		p.lock.Unlock()

		if spent || r.PathValue("token") != "dogru" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "İmza bağlantısı geçersiz ya da süresi dolmuş."})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization": "Örnek Derneği", "document_no": "06-061-115-2026-22", "subject": "Şenlik daveti",
			"step": "signature", "step_label": "Elektronik imza", "filename": "PaketOzeti.xml",
			"content": base64.StdEncoding.EncodeToString([]byte(digest)), "profile": "XL", "timestamp": p.timestamp,
		})
	})
	mux.HandleFunc("POST /imza/{token}", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Signature string `json:"signature"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		signature, _ := base64.StdEncoding.DecodeString(body.Signature)

		p.lock.Lock()
		p.signature = signature
		p.lock.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{"message": "Elektronik imza pakete eklendi.", "complete": false})
	})

	return mux
}

func pfx(t *testing.T) string {
	t.Helper()

	certificate, key := testpki.Certificate(t, "Ayşe Yılmaz", false)

	data, err := pkcs12.Legacy.Encode(key, certificate, nil, "parola")
	if err != nil {
		t.Fatal(err)
	}

	return base64.StdEncoding.EncodeToString(data)
}

type bridge struct {
	t      *testing.T
	server *httptest.Server
	token  string
}

func start(t *testing.T, allowPFX bool) *bridge {
	t.Helper()

	settings, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}

	handler := (&Server{Engine: engine.Native{}, Portal: portal.New(), Config: settings, AllowPFX: allowPFX, Version: "test"}).Handler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()

	match := regexp.MustCompile(`var token = "([0-9a-f]{64})"`).FindSubmatch(body)
	if match == nil {
		t.Fatalf("sayfada gizli anahtar yok: %.200s", body)
	}

	return &bridge{t: t, server: server, token: string(match[1])}
}

func (b *bridge) call(path string, body map[string]string, headers map[string]string) (int, map[string]any) {
	b.t.Helper()

	payload, _ := json.Marshal(body)
	request, _ := http.NewRequest(http.MethodPost, b.server.URL+path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Bridge-Token", b.token)
	for key, value := range headers {
		if key == "Host" {
			request.Host = value
		} else {
			request.Header.Set(key, value)
		}
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		b.t.Fatal(err)
	}
	defer response.Body.Close()

	result := map[string]any{}
	_ = json.NewDecoder(response.Body).Decode(&result)

	return response.StatusCode, result
}

func TestSigningThroughThePortal(t *testing.T) {
	fake := &fakePortal{}
	portalServer := httptest.NewServer(fake.handler())
	defer portalServer.Close()

	b := start(t, true)
	link := portalServer.URL + "/imza/dogru"

	// A portal that is not trusted yet is not contacted.
	status, result := b.call("/api/session", map[string]string{"link": link}, nil)
	if status != http.StatusOK || result["trusted"] != false || result["origin"] != portalServer.URL || fake.fetched != 0 {
		t.Fatalf("güvenilmeyen portal: %d %v, istek sayısı %d", status, result, fake.fetched)
	}

	if status, _ = b.call("/api/sign", map[string]string{"link": link, "source": "pfx", "pfx": pfx(t), "password": "parola"}, nil); status != http.StatusForbidden {
		t.Fatalf("güvenilmeyen portal için imza atıldı: %d", status)
	}

	if status, _ = b.call("/api/trust", map[string]string{"link": link}, nil); status != http.StatusOK {
		t.Fatalf("portala güvenilemedi: %d", status)
	}

	status, result = b.call("/api/session", map[string]string{"link": "  " + link + "\n"}, nil)
	if status != http.StatusOK || result["trusted"] != true || result["document_no"] != "06-061-115-2026-22" || result["subject"] != "Şenlik daveti" || result["timestamp"] != false {
		t.Fatalf("oturum bilgisi: %d %v", status, result)
	}

	if status, result = b.call("/api/sign", map[string]string{"link": link, "source": "pfx", "pfx": pfx(t), "password": "yanlis"}, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("yanlış parola kabul edildi: %d %v", status, result)
	}

	status, result = b.call("/api/sign", map[string]string{"link": link, "source": "pfx", "pfx": pfx(t), "password": "parola"}, nil)
	if status != http.StatusOK || result["signer"] != "Ayşe Yılmaz" || result["profile"] != "BES" || result["message"] != "Elektronik imza pakete eklendi." {
		t.Fatalf("imza: %d %v", status, result)
	}

	// The portal got a CMS signature that carries the digest inside it.
	if len(fake.signature) == 0 || fake.signature[0] != 0x30 || !bytes.Contains(fake.signature, []byte(digest)) {
		t.Fatalf("portala giden imza tümleşik CAdES değil (%d bayt)", len(fake.signature))
	}

	// The link is spent.
	if status, result = b.call("/api/session", map[string]string{"link": link}, nil); status != http.StatusBadGateway || !strings.Contains(result["message"].(string), "geçersiz") {
		t.Fatalf("harcanmış bağlantı: %d %v", status, result)
	}
}

func TestSignatureIsTimestampedWhenThePortalLendsAService(t *testing.T) {
	service := testpki.TimestampService(t, "1234", "gizli")
	fake := &fakePortal{timestamp: map[string]string{"url": service.URL, "user": "1234", "password": "gizli"}}
	portalServer := httptest.NewServer(fake.handler())
	defer portalServer.Close()

	b := start(t, true)
	link := portalServer.URL + "/imza/dogru"
	b.call("/api/trust", map[string]string{"link": link}, nil)

	if _, result := b.call("/api/session", map[string]string{"link": link}, nil); result["timestamp"] != true || result["profile"] != "XL" {
		t.Fatalf("oturum bilgisi: %v", result)
	}

	// The long-term level is not built yet: the signature is time-stamped and the page is told so.
	status, result := b.call("/api/sign", map[string]string{"link": link, "source": "pfx", "pfx": pfx(t), "password": "parola"}, nil)
	if status != http.StatusOK || result["profile"] != "T" || result["asked"] != "XL" {
		t.Fatalf("imza: %d %v", status, result)
	}

	parsed, err := pkcs7.Parse(fake.signature)
	if err != nil || parsed.Verify() != nil || len(parsed.Signers[0].UnauthenticatedAttributes) != 1 {
		t.Fatalf("portala giden imza zaman damgalı değil: %v", err)
	}
}

func TestSignatureIsNotSentWhenTheTimestampServiceFails(t *testing.T) {
	fake := &fakePortal{timestamp: map[string]string{"url": "http://127.0.0.1:1/zd", "user": "1234", "password": "gizli"}}
	portalServer := httptest.NewServer(fake.handler())
	defer portalServer.Close()

	b := start(t, true)
	link := portalServer.URL + "/imza/dogru"
	b.call("/api/trust", map[string]string{"link": link}, nil)

	status, result := b.call("/api/sign", map[string]string{"link": link, "source": "pfx", "pfx": pfx(t), "password": "parola"}, nil)
	if status != http.StatusUnprocessableEntity || !strings.Contains(result["message"].(string), "zaman damgası") || fake.signature != nil {
		t.Fatalf("zaman damgası alınamadan imza gönderildi: %d %v", status, result)
	}
}

func TestTheApiAnswersOnlyToItsOwnPage(t *testing.T) {
	b := start(t, false)
	body := map[string]string{"link": "https://portal.example.org/imza/x"}

	for name, headers := range map[string]map[string]string{
		"gizli anahtar yok":    {"X-Bridge-Token": ""},
		"yanlış gizli anahtar": {"X-Bridge-Token": strings.Repeat("0", 64)},
		"başka site":           {"Origin": "https://kotu.example.org"},
		"başka ad":             {"Host": "kotu.example.org"},
	} {
		if status, _ := b.call("/api/session", body, headers); status != http.StatusForbidden {
			t.Errorf("%s: %d", name, status)
		}
	}

	if status, result := b.call("/api/session", body, nil); status != http.StatusOK || result["trusted"] != false {
		t.Fatalf("kendi sayfası: %d %v", status, result)
	}

	for _, link := range []string{"http://portal.example.org/imza/x", "ftp://portal.example.org/x", "bağlantı değil"} {
		if status, _ := b.call("/api/session", map[string]string{"link": link}, nil); status != http.StatusUnprocessableEntity {
			t.Errorf("%q kabul edildi: %d", link, status)
		}
	}

	// Loading a key from a file is off unless asked for.
	b.call("/api/trust", body, nil)
	if status, result := b.call("/api/sign", map[string]string{"link": body["link"], "source": "pfx", "pfx": "AAAA"}, nil); status != http.StatusUnprocessableEntity || !strings.Contains(result["message"].(string), "kapalı") {
		t.Fatalf("dosyadan sertifika: %d %v", status, result)
	}
}
