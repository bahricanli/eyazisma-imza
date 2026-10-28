package engine

import (
	"debug/macho"
	"fmt"
	"path/filepath"
)

// Inspect the binary itself instead of guessing from a driver's filename.
func driverArchitectureWarning(path, platform, architecture string) error {
	if platform != "darwin" {
		return nil
	}
	var supported []macho.Cpu
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		for _, slice := range fat.Arches {
			supported = append(supported, slice.Cpu)
		}
	} else if file, err := macho.Open(path); err == nil {
		defer file.Close()
		supported = append(supported, file.Cpu)
	}
	wanted := macho.CpuArm64
	if architecture == "amd64" {
		wanted = macho.CpuAmd64
	} else if architecture != "arm64" {
		return nil
	}
	for _, cpu := range supported {
		if cpu == wanted {
			return nil
		}
	}
	if len(supported) == 0 {
		return nil
	}
	if architecture == "arm64" {
		return fmt.Errorf("%s: Kurulu kart sürücüsü Apple Silicon (ARM64) ile uyumlu değil. Sağlayıcınızın ARM64 sürücüsünü kurun. Geçici olarak eyazisma-imza-macos-intel sürümünü Rosetta ile kullanabilirsiniz. ARM64 OpenSC sürücüsü de her kartı desteklemez; okuyucunun görünmesi kartın desteklendiği anlamına gelmez", filepath.Base(path))
	}
	return fmt.Errorf("%s: Kart sürücüsü Intel uygulamasıyla uyumlu değil. ARM64 sürücü için eyazisma-imza-macos-arm64 sürümünü kullanın", filepath.Base(path))
}
