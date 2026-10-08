// Command eyazisma-imza is the signing bridge of the e-Yazışma module of the
// association portal: it runs on the signer's computer, signs the digest a
// portal hands out with the signer's card and returns the signature.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/bahricanli/eyazisma-imza/internal/config"
	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/portal"
	"github.com/bahricanli/eyazisma-imza/internal/server"
)

// version is set at build time.
var version = "dev"

func main() {
	port := flag.Int("port", 51515, "uygulamanın bu bilgisayarda dinleyeceği port")
	configPath := flag.String("config", "", "ayar dosyası (varsayılan: kullanıcının ayar dizini)")
	noBrowser := flag.Bool("no-browser", false, "sayfayı tarayıcıda açma")
	allowPFX := flag.Bool("pfx", false, "sınama için sertifikanın dosyadan yüklenmesine izin ver")
	showVersion := flag.Bool("version", false, "sürümü yaz ve çık")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)

		return
	}

	path := *configPath
	if path == "" {
		var err error
		if path, err = config.DefaultPath(); err != nil {
			log.Fatalf("ayar dizini bulunamadı: %v", err)
		}
	}

	settings, err := config.Load(path)
	if err != nil {
		log.Fatalf("ayar dosyası okunamadı (%s): %v", path, err)
	}

	bridge := &server.Server{Engine: engine.Eimza{}, Portal: portal.New(), Config: settings, AllowPFX: *allowPFX, Version: version}

	// Only this computer can reach the bridge.
	address := fmt.Sprintf("127.0.0.1:%d", *port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("%s dinlenemedi; uygulama zaten açık olabilir: %v", address, err)
	}

	url := "http://" + address + "/"
	fmt.Println("e-Yazışma imza uygulaması çalışıyor:", url)
	fmt.Println("Kapatmak için bu pencereyi kapatın ya da Ctrl+C'ye basın.")

	if !*noBrowser {
		openBrowser(url)
	}

	httpServer := &http.Server{Handler: bridge.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if err := httpServer.Serve(listener); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func openBrowser(url string) {
	var command *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}

	_ = command.Start()
}
