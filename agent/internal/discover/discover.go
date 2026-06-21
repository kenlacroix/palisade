// Package discover enumerates locally listening TCP services by parsing
// /proc/net/tcp and /proc/net/tcp6. Discovery is on-host only: no internal
// traffic leaves the network, only the normalized asset inventory.
package discover

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"palisade/agent/internal/catalog"
)

// tcpStateListen is the /proc/net/tcp st column value for LISTEN (0x0A).
const tcpStateListen = 0x0A

// wellKnown maps a listening port to a best-effort service guess.
var wellKnown = map[int]string{
	4000:  "litellm",
	13378: "audiobookshelf",
	3000:  "nextjs",
	11434: "ollama",
	9000:  "minio",
}

// procFiles are the proc sources parsed for listening sockets. Overridable in
// tests.
var procFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// listener is one parsed LISTEN-state socket.
type listener struct {
	ip   net.IP
	port int
}

// Discover returns the set of locally listening TCP services as Assets.
// hostname is used as the Asset.Host. scope is accepted for interface parity
// with the discover job payload; subnet sweeping is out of scope for this
// scaffold (on-host /proc enumeration only).
func Discover(hostname string, _ *catalog.Scope) ([]catalog.Asset, error) {
	seen := make(map[int]bool)
	var assets []catalog.Asset

	for _, f := range procFiles {
		ls, err := parseProcFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue // tcp6 may be absent on IPv4-only hosts
			}
			return nil, err
		}
		for _, l := range ls {
			if seen[l.port] {
				continue
			}
			seen[l.port] = true
			assets = append(assets, catalog.Asset{
				Host:     hostname,
				Port:     l.port,
				Service:  serviceFor(l.port),
				Product:  nil, // best-effort version/product detection is out of scope
				Version:  nil,
				Exposure: exposureFor(l.ip),
			})
		}
	}
	return assets, nil
}

func serviceFor(port int) string {
	if s, ok := wellKnown[port]; ok {
		return s
	}
	return "unknown"
}

// exposureFor classifies a bind address. Loopback and private (RFC1918 / link
// local / ULA) addresses are internal; anything else (including 0.0.0.0 / ::,
// which bind all interfaces) is treated as external.
func exposureFor(ip net.IP) string {
	if ip.IsLoopback() {
		return "internal"
	}
	if ip.IsUnspecified() {
		return "external" // 0.0.0.0 / :: reachable on all interfaces
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "internal"
	}
	return "external"
}

func parseProcFile(path string) ([]listener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []listener
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first { // header row
			first = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// fields[3] is the connection state (hex).
		st, err := strconv.ParseInt(fields[3], 16, 32)
		if err != nil || st != tcpStateListen {
			continue
		}
		ip, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		out = append(out, listener{ip: ip, port: port})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

// parseHexAddr parses a "<hexaddr>:<hexport>" local_address field from
// /proc/net/tcp{,6}. IPv4 is 8 hex chars (little-endian), IPv6 is 32.
func parseHexAddr(s string) (net.IP, int, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	hexIP, hexPort := s[:i], s[i+1:]

	port64, err := strconv.ParseInt(hexPort, 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port %q: %w", hexPort, err)
	}

	raw, err := hexToBytes(hexIP)
	if err != nil {
		return nil, 0, err
	}

	switch len(raw) {
	case 4:
		// IPv4: kernel writes the address as a little-endian 32-bit word.
		v := binary.LittleEndian.Uint32(raw)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, v)
		return ip, int(port64), nil
	case 16:
		// IPv6: four little-endian 32-bit words.
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			v := binary.LittleEndian.Uint32(raw[w*4 : w*4+4])
			binary.BigEndian.PutUint32(ip[w*4:w*4+4], v)
		}
		return ip, int(port64), nil
	default:
		return nil, 0, fmt.Errorf("unexpected addr length %d", len(raw))
	}
}

func hexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		b, err := strconv.ParseInt(s[i*2:i*2+2], 16, 16)
		if err != nil {
			return nil, fmt.Errorf("bad hex %q: %w", s, err)
		}
		out[i] = byte(b)
	}
	return out, nil
}
