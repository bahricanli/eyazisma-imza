// Package nativebridge implements the browser's length-prefixed local protocol.
// It launches the existing confirmation UI; PINs and signatures never cross it.
package nativebridge

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
)

const HostName = "com.bahricanli.eyazisma_imza"
const FirefoxID = "eyazisma-imza@bahricanli.com"
const ChromeID = "gdfahhbabofbcgphlaphkegkbahlgjhl"
const maxMessage = 64 * 1024

var tokenPath = regexp.MustCompile(`^/imza/[A-Za-z0-9_-]{16,256}$`)

type Request struct {
	Action string `json:"action"`
	Link   string `json:"link,omitempty"`
}
type Response struct {
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"`
	Message string `json:"message,omitempty"`
}

func ValidateLink(link string) error {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !tokenPath.MatchString(u.Path) {
		return errors.New("geçersiz imza bağlantısı")
	}
	if u.Host != "portal.lkd.org.tr" && u.Host != "portal.pkd.org.tr" {
		return errors.New("bu portal tarayıcı bağlantısında desteklenmiyor")
	}
	return nil
}

// Serve accepts only bounded requests. No request content is written to logs.
func Serve(input io.Reader, output io.Writer, version string, launch func(string) error) error {
	for {
		var size uint32
		if err := binary.Read(input, binary.LittleEndian, &size); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size == 0 || size > maxMessage {
			return errors.New("geçersiz ileti boyutu")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(input, data); err != nil {
			return err
		}
		var request Request
		response := Response{Version: version}
		if err := json.Unmarshal(data, &request); err != nil {
			response.Message = "İstek anlaşılamadı."
		} else {
			switch request.Action {
			case "status":
				response.OK = true
			case "cards":
				if err := launch(""); err != nil {
					response.Message = err.Error()
				} else {
					response.OK = true
				}
			case "open":
				if err := ValidateLink(request.Link); err != nil {
					response.Message = err.Error()
				} else if err := launch(request.Link); err != nil {
					response.Message = err.Error()
				} else {
					response.OK = true
				}
			default:
				response.Message = "Desteklenmeyen işlem."
			}
		}
		body, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if err := binary.Write(output, binary.LittleEndian, uint32(len(body))); err != nil {
			return err
		}
		if _, err := output.Write(body); err != nil {
			return err
		}
	}
}
