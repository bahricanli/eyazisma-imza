// Command eyazisma-imza is the signing bridge of the e-Yazışma module of the
// association portal: it runs on the signer's computer, signs the digest a
// portal hands out with the signer's card and returns the signature.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bahricanli/eyazisma-imza/internal/autostart"
	"github.com/bahricanli/eyazisma-imza/internal/config"
	"github.com/bahricanli/eyazisma-imza/internal/engine"
	"github.com/bahricanli/eyazisma-imza/internal/localtls"
	"github.com/bahricanli/eyazisma-imza/internal/portal"
	"github.com/bahricanli/eyazisma-imza/internal/server"
	"github.com/bahricanli/eyazisma-imza/internal/token"
	"golang.org/x/term"
)

// version is set at build time.
var version = "dev"

func main() {
	port := flag.Int("port", 51515, "uygulamanın bu bilgisayarda dinleyeceği port")
	configPath := flag.String("config", "", "ayar dosyası (varsayılan: kullanıcının ayar dizini)")
	noBrowser := flag.Bool("no-browser", false, "sayfayı tarayıcıda açma")
	allowPFX := flag.Bool("pfx", false, "sınama için sertifikanın dosyadan yüklenmesine izin ver")
	driver := flag.String("pkcs11", os.Getenv("EYAZISMA_IMZA_PKCS11"), "yalnız bu akıllı kart sürücüsünü (PKCS#11) kullan; boşsa bilinen yerlerdekiler denenir")
	signFile := flag.String("sign", "", "portal olmadan sınama: bu dosyayı karttaki e-imzayla imzala ve çık")
	output := flag.String("out", "", "--sign ile: imzanın yazılacağı dosya (varsayılan: <dosya>.imz)")
	timestampURL := flag.String("tsa", "", "--sign ile: zaman damgası hizmetinin adresi; verilmezse imza zaman damgasız atılır")
	enableHTTPS := flag.Bool("https", false, "bu bilgisayara özel bir HTTPS sertifikası üret ve sisteme tanıt; uygulama HTTPS ile de dinler")
	disableHTTPS := flag.Bool("no-https", false, "HTTPS sertifikasını sistemden ve bu bilgisayardan kaldır")
	install := flag.Bool("install", false, "uygulamayı oturum açılışında arka planda başlayacak şekilde kaydet ve başlat")
	uninstall := flag.Bool("uninstall", false, "oturum açılışındaki kaydı kaldır ve arka plandaki uygulamayı durdur")
	listCards := flag.Bool("cards", false, "takılı kartları ve PIN'siz görünen sertifikaları listele ve çık (PIN kullanılmaz)")
	showVersion := flag.Bool("version", false, "sürümü yaz ve çık")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)

		return
	}

	if *enableHTTPS || *disableHTTPS {
		if err := secure(*enableHTTPS, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, "Hata:", err)
			os.Exit(1)
		}

		return
	}

	if *install || *uninstall {
		if err := service(*install, *port, *driver, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, "Hata:", err)
			os.Exit(1)
		}

		return
	}

	if *listCards {
		cards(*driver)

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

	handler := bridge.Handler()

	// With this computer's certificate in place the bridge also listens over
	// HTTPS on the next port, for browsers that keep HTTPS pages from plain HTTP.
	if certificate, err := localtls.Load(filepath.Dir(path)); err == nil {
		secureAddress := fmt.Sprintf("127.0.0.1:%d", *port+1)

		if secureListener, err := tls.Listen("tcp", secureAddress, &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12}); err == nil {
			fmt.Println("HTTPS adresi: https://" + secureAddress + "/")

			go func() {
				_ = (&http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}).Serve(secureListener)
			}()
		} else {
			fmt.Fprintln(os.Stderr, "HTTPS dinlenemedi:", err)
		}
	}
	fmt.Println("Kapatmak için bu pencereyi kapatın ya da Ctrl+C'ye basın.")

	if !*noBrowser {
		openBrowser(url)
	}

	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
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

// secure makes and trusts this computer's HTTPS certificate, or removes it.
func secure(enable bool, configPath string) error {
	path := configPath
	if path == "" {
		var err error
		if path, err = config.DefaultPath(); err != nil {
			return err
		}
	}

	directory := filepath.Dir(path)

	if !enable {
		if err := localtls.Remove(directory); err != nil {
			return err
		}

		fmt.Println("HTTPS sertifikası kaldırıldı. Çalışan uygulamayı yeniden başlatın.")

		return nil
	}

	if _, err := localtls.Load(directory); err != nil {
		if err := localtls.Generate(directory); err != nil {
			return err
		}
	}

	certificate, _ := localtls.Paths(directory)
	fmt.Println("Bu bilgisayara özel sertifika:", certificate)
	fmt.Println("Sistem, sertifikaya güvenmek için onayınızı isteyebilir.")

	if err := localtls.Trust(directory); err != nil {
		return fmt.Errorf("sertifika sisteme tanıtılamadı: %w", err)
	}

	fmt.Println("Sertifika tanıtıldı. Çalışan uygulamayı yeniden başlatın (servis kuruluysa --install).")

	return nil
}

// service registers the bridge to run in the background from login on, or removes that.
func service(install bool, port int, driver, configPath string) error {
	if !install {
		if err := autostart.Uninstall(); err != nil {
			return err
		}

		fmt.Println("Uygulama artık oturum açılışında başlamayacak.")

		return nil
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}

	// The background copy opens no browser window; the portal opens the page when a letter is signed.
	arguments := []string{"--no-browser", "--port", fmt.Sprint(port)}
	if driver != "" {
		arguments = append(arguments, "--pkcs11", driver)
	}
	if configPath != "" {
		arguments = append(arguments, "--config", configPath)
	}

	where, err := autostart.Install(executable, arguments)
	if err != nil {
		return err
	}

	fmt.Println("Uygulama oturum açılışında arka planda başlayacak:", where)
	fmt.Printf("Adresi: http://127.0.0.1:%d/\n", port)

	return nil
}

// cards prints what the drivers see, without logging in to any card.
func cards(driver string) {
	found, problems := token.List(driver)

	fmt.Println("Bulunan sürücüler:", strings.Join(token.Drivers(driver), ", "))

	for _, problem := range problems {
		fmt.Println("Uyarı:", problem)
	}

	if len(found) == 0 {
		fmt.Println("Hiçbir sürücü takılı bir kart görmüyor.")

		return
	}

	for _, card := range found {
		fmt.Printf("\nKart: %s (%s)\nSürücü: %s\n", strings.TrimSpace(card.Label), strings.TrimSpace(card.Model), card.Driver)

		if len(card.Certificates) == 0 {
			fmt.Println("  PIN girilmeden görünen sertifika yok.")
		}

		for _, certificate := range card.Certificates {
			mark := " "
			if card.Chosen != nil && certificate.Equal(card.Chosen) {
				mark = "*"
			}

			fmt.Printf("  %s %s | veren: %s | bitiş: %s | CA: %t | inkâr edilemezlik: %t\n", mark, certificate.Subject.CommonName, certificate.Issuer.CommonName,
				certificate.NotAfter.Format("02.01.2006"), certificate.IsCA, certificate.KeyUsage&x509.KeyUsageContentCommitment != 0)
		}
	}

	fmt.Println("\n* imzada kullanılacak sertifika")
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
