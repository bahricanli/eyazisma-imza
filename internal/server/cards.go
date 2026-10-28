package server

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"runtime"

	"github.com/bahricanli/eyazisma-imza/internal/engine"
)

type cardChoice struct {
	link string
	card engine.Card
}

// cards reads public certificate data only; it never asks for or uses a PIN.
func (s *Server) cards(w http.ResponseWriter, r *http.Request) {
	input, origin, ok := s.read(w, r)
	if !ok {
		return
	}
	if !s.Config.Trusts(origin) {
		fail(w, http.StatusForbidden, "Önce bu portala güvenin.")
		return
	}
	selector, ok := s.Engine.(engine.CardSelector)
	if !ok {
		fail(w, http.StatusUnprocessableEntity, "Bu sürüm kart seçimini desteklemiyor.")
		return
	}
	s.hardware.Lock()
	defer s.hardware.Unlock()
	s.choices = make(map[string]cardChoice)
	cards, err := selector.Cards()
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	type item struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	}
	result := make([]item, 0, len(cards))
	for _, card := range cards {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			fail(w, http.StatusInternalServerError, "Kart seçimi oluşturulamadı.")
			return
		}
		id := hex.EncodeToString(bytes)
		s.choices[id] = cardChoice{link: input.Link, card: card}
		result = append(result, item{ID: id, Label: card.Label})
	}
	respond(w, map[string]any{"cards": result})
}

// cardIndex is a local diagnostic page; no portal or signing session is needed.
func (s *Server) cardIndex(w http.ResponseWriter, r *http.Request) {
	if !local(r.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = template.Must(template.New("cards").Parse(cardsPage+driverHelp)).Execute(w, map[string]string{"Token": s.token, "Version": s.versionLabel(), "Platform": runtime.GOOS + "/" + runtime.GOARCH})
}

// localCards never creates signing choices or contacts a portal.
func (s *Server) localCards(w http.ResponseWriter, r *http.Request) {
	selector, ok := s.Engine.(engine.CardSelector)
	if !ok {
		fail(w, http.StatusUnprocessableEntity, "Bu sürüm kart listelemeyi desteklemiyor.")
		return
	}
	s.hardware.Lock()
	defer s.hardware.Unlock()
	cards, err := selector.Cards()
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	labels := make([]string, 0, len(cards))
	for _, card := range cards {
		labels = append(labels, card.Label)
	}
	respond(w, map[string]any{"cards": labels})
}
