// Package server is the bridge's page on this computer: it shows what a
// portal wants signed, asks for the PIN and returns the signature.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/bahricanli/eyazisma-imza/internal/config"
	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/portal"
)

//go:embed page.html
var page string

type Server struct {
	Engine engine.Engine
	Portal *portal.Client
	Config *config.Config
	// AllowPFX lets a key be loaded from a file instead of a card; for testing only.
	AllowPFX bool
	Version  string

	token    string
	template *template.Template
}

// Handler serves the page and its API. The API answers only to the page
// itself: a secret put in the page must come back with every call, and the
// request must be addressed to this computer.
func (s *Server) Handler() http.Handler {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	s.token = hex.EncodeToString(secret)
	s.template = template.Must(template.New("page").Parse(page))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("OPTIONS /status", s.status)
	mux.HandleFunc("POST /api/session", s.guard(s.session))
	mux.HandleFunc("POST /api/trust", s.guard(s.trust))
	mux.HandleFunc("POST /api/sign", s.guard(s.sign))

	return mux
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if !local(r.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = s.template.Execute(w, map[string]any{"Token": s.token, "AllowPFX": s.AllowPFX, "Version": s.Version})
}

// status lets a portal page see that the bridge is running. It gives away
// nothing but the version, so any page may ask; signing still goes through
// the bridge's own page.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if !local(r.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)

		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Browsers ask before letting a public page reach this computer.
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)

		return
	}

	respond(w, map[string]any{"name": "eyazisma-imza", "version": s.Version})
}

func (s *Server) guard(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		ownOrigin := origin == "" || origin == "http://"+r.Host || origin == "https://"+r.Host

		if !local(r.Host) || !ownOrigin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Bridge-Token")), []byte(s.token)) != 1 {
			fail(w, http.StatusForbidden, "Bu istek imza uygulamasının kendi sayfasından gelmiyor.")

			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		next(w, r)
	}
}

type request struct {
	Link     string `json:"link"`
	Source   string `json:"source"`
	PIN      string `json:"pin"`
	PFX      string `json:"pfx"`
	Password string `json:"password"`
}

// session tells the page what the link asks for. A portal not trusted yet
// is not contacted; the page asks the user first.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	input, origin, ok := s.read(w, r)
	if !ok {
		return
	}

	if !s.Config.Trusts(origin) {
		respond(w, map[string]any{"origin": origin, "trusted": false})

		return
	}

	session, err := s.Portal.Fetch(input.Link)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())

		return
	}

	respond(w, map[string]any{
		"origin":       origin,
		"trusted":      true,
		"organization": session.Organization,
		"document_no":  session.DocumentNo,
		"subject":      session.Subject,
		"step_label":   session.StepLabel,
		"filename":     session.Filename,
		"profile":      session.Profile,
		"timestamp":    session.Timestamp != nil && session.Timestamp.URL != "",
		"expires_at":   session.ExpiresAt,
	})
}

func (s *Server) trust(w http.ResponseWriter, r *http.Request) {
	_, origin, ok := s.read(w, r)
	if !ok {
		return
	}

	if err := s.Config.Trust(origin); err != nil {
		fail(w, http.StatusInternalServerError, "Portal kaydedilemedi: "+err.Error())

		return
	}

	respond(w, map[string]any{"origin": origin, "trusted": true})
}

func (s *Server) sign(w http.ResponseWriter, r *http.Request) {
	input, origin, ok := s.read(w, r)
	if !ok {
		return
	}

	if !s.Config.Trusts(origin) {
		fail(w, http.StatusForbidden, "Bu portala güvenilmiyor: "+origin)

		return
	}

	key, err := s.open(input)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())

		return
	}
	defer key.Close()

	session, err := s.Portal.Fetch(input.Link)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())

		return
	}

	document, err := session.Document()
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())

		return
	}

	var timestamp *engine.Timestamp
	if session.Timestamp != nil && session.Timestamp.URL != "" {
		timestamp = &engine.Timestamp{URL: session.Timestamp.URL, User: session.Timestamp.User, Password: session.Timestamp.Password}
	}

	signature, reached, err := s.Engine.Sign(document, key, engine.Profile(session.Profile), timestamp)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())

		return
	}

	result, err := s.Portal.Submit(input.Link, signature)
	if err != nil {
		fail(w, http.StatusBadGateway, err.Error())

		return
	}

	respond(w, map[string]any{
		"message":  result.Message,
		"complete": result.Complete,
		"signer":   key.Certificate.Subject.CommonName,
		"profile":  string(reached),
		"asked":    session.Profile,
	})
}

func (s *Server) open(input *request) (*engine.Key, error) {
	if input.Source == "pfx" {
		if !s.AllowPFX {
			return nil, errors.New("Dosyadan sertifika yükleme kapalı.")
		}

		data, err := base64.StdEncoding.DecodeString(input.PFX)
		if err != nil || len(data) == 0 {
			return nil, errors.New("PFX dosyası okunamadı.")
		}

		return s.Engine.OpenPFX(data, input.Password)
	}

	return s.Engine.OpenCard(input.PIN)
}

func (s *Server) read(w http.ResponseWriter, r *http.Request) (*request, string, bool) {
	input := &request{}
	if err := json.NewDecoder(r.Body).Decode(input); err != nil {
		fail(w, http.StatusBadRequest, "İstek anlaşılamadı.")

		return nil, "", false
	}

	input.Link = strings.TrimSpace(input.Link)

	origin, err := portal.Origin(input.Link)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())

		return nil, "", false
	}

	return input, origin, true
}

// local reports whether the request was addressed to this computer, which
// stops another site from reaching the bridge under its own host name.
func local(host string) bool {
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		name = host
	}

	return name == "127.0.0.1" || name == "localhost"
}

func respond(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
