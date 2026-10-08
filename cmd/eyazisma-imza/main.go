// Command eyazisma-imza is the signing bridge of the e-Yazışma module of the
// association portal: it runs on the signer's computer, signs the digest a
// portal hands out with the signer's card and returns the signature.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bahricanli/eyazisma-imza/internal/config"
	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/portal"
	"github.com/bahricanli/eyazisma-imza/internal/server"
	"golang.org/x/term"
)

// version is set at build time.
var version = "dev"

func main() {
	port := flag.Int("port", 51515, "uygulamanın bu bilgisayarda dinleyeceği port")
	configPath := flag.String("config", "", "ayar dosyası (varsayılan: kullanıcının ayar dizini)")
	noBrowser := flag.Bool("no-browser", false, "sayfayı tarayıcıda açma")
	allowPFX := flag.Bool("pfx", false, "sınama için sertifikanın dosyadan yüklenmesine izin ver")
	driver := flag.String("pkcs11", os.Getenv("EYAZISMA_IMZA_PKCS11"), "akıllı kart sürücüsünün (PKCS#11) yolu; boşsa bilinen yerler denenir")
	signFile := flag.String("sign", "", "portal olmadan sınama: bu dosyayı karttaki e-imzayla imzala ve çık")
	output := flag.String("out", "", "--sign ile: imzanın yazılacağı dosya (varsayılan: <dosya>.imz)")
	timestampURL := flag.String("tsa", "", "--sign ile: zaman damgası hizmetinin adresi; verilmezse imza zaman damgasız atılır")
	showVersion := flag.Bool("version", false, "sürümü yaz ve çık")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)

		return
	}

	if *signFile != "" {
		if err := signOnce(engine.Native{Driver: *driver}, *signFile, *output, *timestampURL); err != nil {
			fmt.Fprintln(os.Stderr, "Hata:", err)
			os.Exit(1)
		}

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

	bridge := &server.Server{Engine: engine.Native{Driver: *driver}, Portal: portal.New(), Config: settings, AllowPFX: *allowPFX, Version: version}

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

// signOnce signs a file with the card without a portal, to try a card and its driver out.
func signOnce(signer engine.Engine, input, output, timestampURL string) error {
	content, err := os.ReadFile(input)
	if err != nil {
		return err
	}

	pin, err := readPIN()
	if err != nil {
		return fmt.Errorf("PIN okunamadı: %w", err)
	}

	key, err := signer.OpenCard(pin)
	if err != nil {
		return err
	}
	defer key.Close()

	fmt.Println("Sertifika:", key.Certificate.Subject.CommonName)
	fmt.Println("Veren:", key.Certificate.Issuer.CommonName)
	fmt.Println("Geçerlilik:", key.Certificate.NotBefore.Format("02.01.2006"), "-", key.Certificate.NotAfter.Format("02.01.2006"))

	profile := engine.ProfileBES
	var timestamp *engine.Timestamp
	if timestampURL != "" {
		profile, timestamp = engine.ProfileT, &engine.Timestamp{URL: timestampURL}
	}

	signature, reached, err := signer.Sign(content, key, profile, timestamp)
	if err != nil {
		return err
	}

	if output == "" {
		output = input + ".imz"
	}

	if err := os.WriteFile(output, signature, 0o600); err != nil {
		return err
	}

	fmt.Printf("İmza yazıldı: %s (%d bayt, düzey %s)\n", output, len(signature), reached)

	return nil
}

// readPIN asks for the PIN without showing it; when the input is not a terminal it reads a line.
func readPIN() (string, error) {
	input := int(os.Stdin.Fd())

	if !term.IsTerminal(input) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}

		return strings.TrimSpace(line), nil
	}

	fmt.Fprint(os.Stderr, "PIN: ")
	pin, err := term.ReadPassword(input)
	fmt.Fprintln(os.Stderr)

	return string(pin), err
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
