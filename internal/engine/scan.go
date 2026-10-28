package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/bahricanli/eyazisma-imza/internal/token"
)

// A broken vendor driver may hang or crash in C_Initialize. Public card
// discovery therefore runs in disposable processes that never receive a PIN.
func (e Native) Cards() ([]Card, error) {
	drivers := token.Drivers(e.Driver)
	if len(drivers) == 0 {
		return nil, errors.New("akıllı kart sürücüsü (PKCS#11) bulunamadı; sertifika sağlayıcınızın sürücüsünü kurun")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	var choices []Card
	var problems []error
	for _, driver := range drivers {
		cards, err := scanDriver(executable, driver, 8*time.Second)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		choices = append(choices, cards...)
	}
	if len(choices) > 0 {
		return choices, nil
	}
	return nil, fmt.Errorf("kartlar okunamadı; kartı takın ve kartınıza ait sürücüyü kontrol edin: %w", errors.Join(problems...))
}

func scanDriver(executable, driver string, timeout time.Duration) ([]Card, error) {
	if err := driverArchitectureWarning(driver, runtime.GOOS, runtime.GOARCH); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "--cards-json", "--pkcs11", driver)
	output, err := command.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s sürücüsü yanıt vermedi", filepath.Base(driver))
	}
	if err != nil {
		return nil, fmt.Errorf("%s sürücüsü çalıştırılamadı", filepath.Base(driver))
	}
	var result struct {
		Cards []Card `json:"cards"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("%s sürücüsünden geçerli kart bilgisi alınamadı", filepath.Base(driver))
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}
	if len(result.Cards) == 0 {
		return nil, errors.New("takılı bir imza kartı bulunamadı")
	}
	return result.Cards, nil
}
