package wg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerStatus is one peer as reported by `wg show ... dump`.
type PeerStatus struct {
	PublicKey          string    `json:"public_key"`
	PresharedKeySet    bool      `json:"preshared_key_set"`
	Endpoint           string    `json:"endpoint"`
	AllowedIPs         []string  `json:"allowed_ips"`
	LatestHandshake    time.Time `json:"latest_handshake"` // zero = never
	LatestHandshakeAgo int64     `json:"latest_handshake_ago_seconds"`
	RXBytes            uint64    `json:"rx_bytes"`
	TXBytes            uint64    `json:"tx_bytes"`
	KeepaliveSeconds   int       `json:"keepalive_seconds"` // 0 = off
}

// InterfaceStatus is one interface plus its peers from the dump.
type InterfaceStatus struct {
	Name       string       `json:"name"`
	PrivateKey string       `json:"private_key,omitempty"`
	PublicKey  string       `json:"public_key,omitempty"`
	ListenPort int          `json:"listen_port"` // 0 = off
	FwMark     uint32       `json:"fwmark"`
	Peers      []PeerStatus `json:"peers"`
}

// ParseDump parses output of `wg show all dump` (interface-prefixed) or
// `wg show <iface> dump` (unprefixed). Lines are tab-separated.
// Returned slices are always non-nil so they marshal as [] not null.
func ParseDump(output string) ([]*InterfaceStatus, error) {
	ifaces := []*InterfaceStatus{}
	byName := map[string]*InterfaceStatus{}
	current := (*InterfaceStatus)(nil)

	for lineNo, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		switch len(f) {
		case 4, 5: // interface line, optionally prefixed with the interface name
			name := ""
			fields := f
			if len(f) == 5 {
				name, fields = f[0], f[1:]
			}
			cur, ok := byName[name]
			if !ok {
				cur = &InterfaceStatus{Name: name, Peers: []PeerStatus{}}
				ifaces = append(ifaces, cur)
				byName[name] = cur
			}
			current = cur
			applyIfaceFields(cur, fields)
		case 8, 9: // peer line, optionally prefixed with the interface name
			cur := current
			fields := f
			if len(f) == 9 {
				var ok bool
				cur, ok = byName[f[0]]
				if !ok {
					return nil, fmt.Errorf("peer line references unknown interface %q", f[0])
				}
				fields = f[1:]
			}
			if cur == nil {
				return nil, fmt.Errorf("peer line before any interface line")
			}
			p, err := parsePeer(fields)
			if err != nil {
				return nil, err
			}
			cur.Peers = append(cur.Peers, *p)
		default:
			// Dump lines contain private keys and PSKs. Never echo a malformed
			// raw line through an API error response.
			return nil, fmt.Errorf("line %d: unexpected field count %d", lineNo+1, len(f))
		}
	}
	if len(ifaces) == 0 && strings.TrimSpace(output) != "" {
		return nil, fmt.Errorf("no interfaces found in dump output")
	}
	return ifaces, nil
}

// "off" and "(none)" sentinels used by wireguard-tools.
func isNone(s string) bool { return s == "off" || s == "(none)" || s == "(hidden)" }

// applyIfaceFields fills interface fields from
// [private-key, public-key, listen-port, fwmark].
// Missing keys use wireguard-tools sentinels: "(none)" / "(hidden)" / "off".
func applyIfaceFields(i *InterfaceStatus, f []string) {
	if !isNone(f[0]) && len(f[0]) > 0 {
		i.PrivateKey = f[0]
	}
	if !isNone(f[1]) && len(f[1]) > 0 {
		i.PublicKey = f[1]
	} else if i.PublicKey == "" && i.PrivateKey != "" {
		i.PublicKey = PublicKeyFromPrivate(i.PrivateKey)
	}
	port, _ := strconv.Atoi(f[2])
	i.ListenPort = port
	if !isNone(f[3]) {
		fw, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(f[3]), "0x"), 16, 32)
		if err == nil {
			i.FwMark = uint32(fw)
		}
	}
}

func parsePeer(f []string) (*PeerStatus, error) {
	p := &PeerStatus{PublicKey: f[0], AllowedIPs: []string{}}
	p.PresharedKeySet = !isNone(f[1])
	if !isNone(f[2]) {
		p.Endpoint = f[2]
	}
	if !isNone(f[3]) {
		for _, ip := range strings.Split(f[3], ",") {
			if s := strings.TrimSpace(ip); s != "" {
				p.AllowedIPs = append(p.AllowedIPs, s)
			}
		}
	}
	secs, _ := strconv.ParseInt(f[4], 10, 64)
	if secs > 0 {
		p.LatestHandshake = time.Unix(secs, 0)
		p.LatestHandshakeAgo = time.Now().Unix() - secs
	}
	rx, _ := strconv.ParseUint(f[5], 10, 64)
	tx, _ := strconv.ParseUint(f[6], 10, 64)
	p.RXBytes, p.TXBytes = rx, tx
	if ka, err := strconv.Atoi(f[7]); err == nil {
		p.KeepaliveSeconds = ka
	}
	return p, nil
}
