package discover

import (
	"net"
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
