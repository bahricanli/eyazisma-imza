package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/testpki"
)

type selectingEngine struct {
	engine.Native
	choices []engine.Card
	key     *engine.Key
	listed  int
	opened  []engine.Card
}

func (e *selectingEngine) Cards() ([]engine.Card, error) { e.listed++; return e.choices, nil }
func (e *selectingEngine) OpenSelectedCard(card engine.Card, pin string) (*engine.Key, error) {
	e.opened = append(e.opened, card)
	return e.key, nil
}
func (e *selectingEngine) OpenCard(pin string) (*engine.Key, error) {
	panic("automatic card choice must not be used by the browser")
}

func TestCardChoiceIsRequiredAndOnlyTheChosenCardIsOpened(t *testing.T) {
	certificate, privateKey := testpki.Certificate(t, "Selected signer", false)
	signer := &selectingEngine{choices: []engine.Card{{Label: "First card"}, {Label: "Second card"}}, key: &engine.Key{Certificate: certificate, Signer: privateKey, Close: func() {}}}
	b := startWithEngine(t, false, signer)
	fake := &fakePortal{}
	portalServer := httptest.NewServer(fake.handler())
	defer portalServer.Close()
	link := portalServer.URL + "/imza/dogru"
	if status, _ := b.call("/api/cards", map[string]string{"link": link}, nil); status != http.StatusForbidden {
		t.Fatalf("untrusted scan: %d", status)
	}
	if signer.listed != 0 {
		t.Fatal("untrusted portal scanned cards")
	}
	b.call("/api/trust", map[string]string{"link": link}, nil)
	if status, _ := b.call("/api/sign", map[string]string{"link": link, "source": "card", "pin": "test-pin"}, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("missing choice accepted: %d", status)
	}
	if len(signer.opened) != 0 {
		t.Fatal("PIN used before card choice")
	}
	status, result := b.call("/api/cards", map[string]string{"link": link}, nil)
	if status != http.StatusOK {
		t.Fatalf("scan: %d %v", status, result)
	}
	choices := result["cards"].([]any)
	if len(choices) != 2 || len(signer.opened) != 0 {
		t.Fatal("scan must list both cards without opening a PIN session")
	}
	card := choices[1].(map[string]any)
	if len(card) != 2 || card["label"] != "Second card" {
		t.Fatalf("public card descriptor: %v", card)
	}
	id := card["id"].(string)
	if status, _ := b.call("/api/sign", map[string]string{"link": portalServer.URL + "/imza/other", "source": "card", "card_id": id, "pin": "test-pin"}, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("choice reused for another document: %d", status)
	}
	if len(signer.opened) != 0 {
		t.Fatal("wrong document tried a PIN")
	}
	if status, result := b.call("/api/sign", map[string]string{"link": link, "source": "card", "card_id": id, "pin": "test-pin"}, nil); status != http.StatusOK || result["signer"] != certificate.Subject.CommonName {
		t.Fatalf("sign: %d %v", status, result)
	}
	if len(signer.opened) != 1 || signer.opened[0].Label != "Second card" {
		t.Fatal("selected card was not used")
	}
}

func TestCardRescanInvalidatesOldChoicesAndUsesTheSameOriginGuard(t *testing.T) {
	signer := &selectingEngine{choices: []engine.Card{{Label: "Only card"}}}
	b := startWithEngine(t, false, signer)
	body := map[string]string{"link": "https://portal.example/imza/x"}
	b.call("/api/trust", body, nil)
	if status, _ := b.call("/api/cards", body, map[string]string{"X-Bridge-Token": ""}); status != http.StatusForbidden {
		t.Fatal("scan without bridge token accepted")
	}
	if status, _ := b.call("/api/cards", body, map[string]string{"Origin": "https://evil.example"}); status != http.StatusForbidden {
		t.Fatal("cross-origin scan accepted")
	}
	_, result := b.call("/api/cards", body, nil)
	oldID := result["cards"].([]any)[0].(map[string]any)["id"].(string)
	b.call("/api/cards", body, nil)
	if status, result := b.call("/api/sign", map[string]string{"link": body["link"], "source": "card", "card_id": oldID, "pin": "test-pin"}, nil); status != http.StatusUnprocessableEntity || !strings.Contains(result["message"].(string), "yeniden") {
		t.Fatalf("stale choice: %d %v", status, result)
	}
	if len(signer.opened) != 0 {
		t.Fatal("stale choice used PIN")
	}
}

func TestLocalCardInspectionNeedsNoPortalAndCannotCreateSigningChoices(t *testing.T) {
	signer := &selectingEngine{choices: []engine.Card{{Label: "Example card — Example signer"}}}
	b := startWithEngine(t, false, signer)
	status, result := b.call("/api/local-cards", map[string]string{}, nil)
	if status != http.StatusOK || len(result["cards"].([]any)) != 1 || signer.listed != 1 {
		t.Fatalf("local inspection: %d %v", status, result)
	}
	if len(signer.opened) != 0 {
		t.Fatal("inspection opened a PIN session")
	}
	for _, headers := range []map[string]string{{"X-Bridge-Token": ""}, {"Origin": "https://evil.example"}} {
		if status, _ := b.call("/api/local-cards", map[string]string{}, headers); status != http.StatusForbidden {
			t.Fatal("unguarded local inspection")
		}
	}
	if signer.listed != 1 {
		t.Fatal("forbidden request scanned cards")
	}
	link := "https://portal.example/imza/test"
	b.call("/api/trust", map[string]string{"link": link}, nil)
	if status, _ := b.call("/api/sign", map[string]string{"link": link, "source": "card", "card_id": "Example card", "pin": "test-pin"}, nil); status != http.StatusUnprocessableEntity {
		t.Fatal("inspection created a signing choice")
	}
	if len(signer.opened) != 0 {
		t.Fatal("inspection allowed signing")
	}
}
