package discover

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseHexAddrIPv4(t *testing.T) {
	// 0100007F:0FA0 = 127.0.0.1:4000 (addr is little-endian).
	ip, port, err := parseHexAddr("0100007F:0FA0")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "127.0.0.1" {
		t.Errorf("ip = %s, want 127.0.0.1", got)
	}
	if port != 4000 {
		t.Errorf("port = %d, want 4000", port)
	}
}

func TestParseHexAddrIPv4Unspecified(t *testing.T) {
	// 00000000:0BB8 = 0.0.0.0:3000
	ip, port, err := parseHexAddr("00000000:0BB8")
	if err != nil {
		t.Fatal(err)
	}
	if !ip.IsUnspecified() {
		t.Errorf("ip = %s, want unspecified", ip)
	}
	if port != 3000 {
		t.Errorf("port = %d, want 3000", port)
	}
}

func TestExposureFor(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"127.0.0.1", "internal"},
		{"192.168.1.10", "internal"},
		{"10.0.0.5", "internal"},
		{"0.0.0.0", "external"},
		{"8.8.8.8", "external"},
		{"::1", "internal"},
	}
	for _, c := range cases {
		got := exposureFor(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("exposureFor(%s) = %s, want %s", c.ip, got, c.want)
		}
	}
}

func TestProbeScheme(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSrv.Close()
	plainSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plainSrv.Close()

	addrOf := func(srvURL string) (net.IP, int) {
		t.Helper()
		i := indexScheme(srvURL)
		if i < 0 {
			t.Fatalf("no scheme in %q", srvURL)
		}
		host, port, err := net.SplitHostPort(srvURL[i:])
		if err != nil {
			t.Fatalf("split %q: %v", srvURL, err)
		}
		p, err := net.LookupPort("tcp", port)
		if err != nil {
			t.Fatalf("port %q: %v", port, err)
		}
		return net.ParseIP(host), p
	}

	if ip, port := addrOf(tlsSrv.URL); probeScheme(ip, port) != "https" {
		t.Errorf("tls server: got %q, want https", probeScheme(ip, port))
	}
	if ip, port := addrOf(plainSrv.URL); probeScheme(ip, port) != "http" {
		t.Errorf("plain server: got %q, want http", probeScheme(ip, port))
	}

	// Closed port: stand a listener up, capture its address, then close it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if got := probeScheme(net.ParseIP("127.0.0.1"), closedPort); got != "" {
		t.Errorf("closed port: got %q, want \"\"", got)
	}
}

func indexScheme(u string) int {
	if i := len("https://"); len(u) > i && u[:i] == "https://" {
		return i
	}
	if i := len("http://"); len(u) > i && u[:i] == "http://" {
		return i
	}
	return -1
}

func TestServiceFor(t *testing.T) {
	if serviceFor(4000) != "litellm" {
		t.Error("4000 should map to litellm")
	}
	if serviceFor(13378) != "audiobookshelf" {
		t.Error("13378 should map to audiobookshelf")
	}
	if serviceFor(22) != "unknown" {
		t.Error("22 should map to unknown")
	}
}
