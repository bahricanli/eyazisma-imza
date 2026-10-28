package nativebridge

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func frame(request Request) []byte {
	data, _ := json.Marshal(request)
	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.LittleEndian, uint32(len(data)))
	b.Write(data)
	return b.Bytes()
}
func TestProtocolOnlyLaunchesValidatedLinksAndCardUI(t *testing.T) {
	good := "https://portal.lkd.org.tr/imza/abcdefghijklmnop1234"
	cases := []struct {
		request Request
		ok      bool
		calls   int
	}{{Request{Action: "status"}, true, 0}, {Request{Action: "cards"}, true, 1}, {Request{Action: "open", Link: good}, true, 1}, {Request{Action: "open", Link: "https://evil.example/imza/abcdefghijklmnop"}, false, 0}, {Request{Action: "sign", Link: good}, false, 0}}
	for _, test := range cases {
		var out bytes.Buffer
		calls := 0
		err := Serve(bytes.NewReader(frame(test.request)), &out, "test", func(string) error { calls++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		var length uint32
		_ = binary.Read(&out, binary.LittleEndian, &length)
		var result Response
		_ = json.Unmarshal(out.Bytes(), &result)
		if result.OK != test.ok || calls != test.calls || strings.Contains(out.String(), good) {
			t.Fatalf("unexpected response: %v", result)
		}
	}
}
func TestLinkValidationRejectsCredentialsPortsQueriesAndEncodedPaths(t *testing.T) {
	for _, link := range []string{"http://portal.lkd.org.tr/imza/abcdefghijklmnop", "https://portal.lkd.org.tr:443/imza/abcdefghijklmnop", "https://user@portal.lkd.org.tr/imza/abcdefghijklmnop", "https://portal.lkd.org.tr/imza/abcdefghijklmnop?secret=1", "https://portal.lkd.org.tr/imza/%61bcdefghijklmnop", "https://portal.lkd.org.tr/imza/abcdefghijklmnop#x"} {
		if ValidateLink(link) == nil {
			t.Fatal("accepted", link)
		}
	}
}
func TestFramesAreBoundedAndCallerIsRestricted(t *testing.T) {
	for _, size := range []uint32{0, maxMessage + 1} {
		var in, out bytes.Buffer
		_ = binary.Write(&in, binary.LittleEndian, size)
		if Serve(&in, &out, "test", func(string) error { return nil }) == nil {
			t.Fatal("invalid size accepted")
		}
	}
	if !Called([]string{"chrome-extension://" + ChromeID + "/"}, ChromeID) || Called([]string{"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"}, ChromeID) {
		t.Fatal("caller check failed")
	}
}
