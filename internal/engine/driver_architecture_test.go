package engine

import (
	"debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDriverArchitectureWarningChecksActualBinary(t *testing.T) {
	for _, cpu := range []macho.Cpu{macho.CpuAmd64, macho.CpuArm64} {
		path := filepath.Join(t.TempDir(), "driver.dylib")
		header := []uint32{0xfeedfacf, uint32(cpu), 0, 6, 0, 0, 0, 0}
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(file, binary.LittleEndian, header); err != nil {
			t.Fatal(err)
		}
		file.Close()
		for _, architecture := range []string{"arm64", "amd64"} {
			err := driverArchitectureWarning(path, "darwin", architecture)
			compatible := (cpu == macho.CpuArm64 && architecture == "arm64") || (cpu == macho.CpuAmd64 && architecture == "amd64")
			if (err == nil) != compatible {
				t.Fatalf("%v/%s: %v", cpu, architecture, err)
			}
			if err != nil && architecture == "arm64" && !strings.Contains(err.Error(), "Rosetta") {
				t.Fatal("missing actionable guidance")
			}
		}
		if err := driverArchitectureWarning(path, "windows", "arm64"); err != nil {
			t.Fatal(err)
		}
	}
	if err := driverArchitectureWarning("missing", "darwin", "arm64"); err != nil {
		t.Fatal("unknown binary was classified")
	}
}
