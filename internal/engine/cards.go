package engine

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/bahricanli/eyazisma-imza/internal/token"
)

// Card is a server-held choice; only its label is returned to the browser.
type Card struct {
	Label     string
	Selection token.Selection
}

type CardSelector interface {
	Cards() ([]Card, error)
	OpenSelectedCard(Card, string) (*Key, error)
}

// CardsInProcess is used only by the isolated, PIN-free scanner subprocess.
func (e Native) CardsInProcess() ([]Card, error) {
	if len(token.Drivers(e.Driver)) == 0 {
		if e.Driver == "opensc" {
			return nil, errors.New("OpenSC sürücüsü bulunamadı. İşletim sisteminize ve uygulamanın mimarisine uygun OpenSC kurun veya --pkcs11 ile sürücü dosyasını belirtin")
		}
		return nil, errors.New("akıllı kart sürücüsü (PKCS#11) bulunamadı; sertifika sağlayıcınızın sürücüsünü kurun")
	}
	cards, problems := token.List(e.Driver)
	var choices []Card
	for _, card := range cards {
		base := token.Selection{Driver: card.Driver, Slot: card.Slot, Serial: card.Serial}
		visible := 0
		hasSigningCertificate := false
		for _, certificate := range card.Certificates {
			if !certificate.IsCA && certificate.KeyUsage&x509.KeyUsageContentCommitment != 0 {
				hasSigningCertificate = true
			}
		}
		for _, certificate := range card.Certificates {
			if hasSigningCertificate && certificate.KeyUsage&x509.KeyUsageContentCommitment == 0 {
				continue
			}
			if certificate.IsCA || (certificate.KeyUsage != 0 && certificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0) {
				continue
			}
			selection := base
			selection.Fingerprint = token.Fingerprint(certificate)
			label := fmt.Sprintf("%s — %s — %s — son geçerlilik: %s", card.Label, certificate.Subject.CommonName, certificate.Issuer.CommonName, certificate.NotAfter.Format("02.01.2006"))
			choices = append(choices, Card{Label: label, Selection: selection})
			visible++
		}
		if visible == 0 && len(card.Certificates) == 0 {
			choices = append(choices, Card{Label: strings.TrimSpace(card.Label+" "+card.Model) + " — sertifika PIN sonrasında okunacak", Selection: base})
		}
	}
	if len(choices) == 0 {
		if len(problems) > 0 {
			return nil, fmt.Errorf("kartlar okunamadı: %w", problems[len(problems)-1])
		}
		return nil, errors.New("imza kartı veya imza sertifikası bulunamadı; kartı takıp yeniden listeleyin")
	}
	return choices, nil
}

func (Native) OpenSelectedCard(choice Card, pin string) (*Key, error) {
	card, err := token.OpenSelected(choice.Selection, pin)
	if err != nil {
		return nil, err
	}
	return &Key{Certificate: card.Certificate, Signer: card, Close: card.Close}, nil
}
