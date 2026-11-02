package config

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var ifaceNameRE = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

// ValidIfaceName matches the names accepted by wg-quick, without traversal.
func ValidIfaceName(name string) bool {
	return ifaceNameRE.MatchString(name) && name != "." && !strings.Contains(name, "..")
}

// Interface mirrors the [Interface] section of a wg-quick configuration.
type Interface struct {
	PrivateKey string   `json:"private_key"`
	ListenPort int      `json:"listen_port"` // 0 = unset
	FwMark     string   `json:"fwmark"`
	Address    []string `json:"address"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	Table      string   `json:"table"`
	PreUp      []string `json:"pre_up"`
	PostUp     []string `json:"post_up"`
	PreDown    []string `json:"pre_down"`
	PostDown   []string `json:"post_down"`
	SaveConfig bool     `json:"save_config"`
}

// Peer mirrors one [Peer] section of a wg configuration.
type Peer struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive"` // -1 = off/unset
}

// Config is a parsed WireGuard / wg-quick configuration file.
type Config struct {
	Interface Interface `json:"interface"`
	Peers     []Peer    `json:"peers"`
}

var ifaceKeys = map[string]struct{}{
	"privatekey": {}, "listenport": {}, "fwmark": {}, "address": {},
	"dns": {}, "mtu": {}, "table": {}, "preup": {}, "postup": {},
	"predown": {}, "postdown": {}, "saveconfig": {},
}

var peerKeys = map[string]struct{}{
	"publickey": {}, "presharedkey": {}, "allowedips": {},
	"endpoint": {}, "persistentkeepalive": {},
}

// Parse parses wg/wg-quick INI-style content.
func Parse(content string) (*Config, error) {
	cfg := &Config{Peers: []Peer{}}
	section := ""
	lineNo := 0
	for _, raw := range strings.Split(content, "\n") {
		lineNo++
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			switch strings.ToLower(strings.Trim(line, "[]")) {
			case "interface":
				section = "interface"
				continue
			case "peer":
				section = "peer"
				cfg.Peers = append(cfg.Peers, Peer{PersistentKeepalive: -1})
				continue
			default:
				return nil, fmt.Errorf("line %d: unknown section", lineNo)
			}
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		var dst any
		switch section {
		case "interface":
			if _, ok := ifaceKeys[key]; !ok {
				return nil, fmt.Errorf("line %d: unknown [Interface] key", lineNo)
			}
			dst = &cfg.Interface
		case "peer":
			if _, ok := peerKeys[key]; !ok {
				return nil, fmt.Errorf("line %d: unknown [Peer] key", lineNo)
			}
			dst = &cfg.Peers[len(cfg.Peers)-1]
		default:
			return nil, fmt.Errorf("line %d: key outside of a section", lineNo)
		}

		if err := applyKV(dst, key, val); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if section == "" {
		return nil, fmt.Errorf("missing [Interface] section")
	}
	if cfg.Interface.PrivateKey == "" && len(cfg.Peers) > 0 {
		return nil, fmt.Errorf("[Interface] PrivateKey is required when peers are defined")
	}
	seen := map[string]bool{}
	for i, p := range cfg.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("peer #%d: PublicKey is required", i+1)
		}
		if seen[p.PublicKey] {
			return nil, fmt.Errorf("peer #%d: duplicate PublicKey", i+1)
		}
		seen[p.PublicKey] = true
	}
	cfg.Interface.Address = nonNilStrings(cfg.Interface.Address)
	cfg.Interface.DNS = nonNilStrings(cfg.Interface.DNS)
	cfg.Interface.PreUp = nonNilStrings(cfg.Interface.PreUp)
	cfg.Interface.PostUp = nonNilStrings(cfg.Interface.PostUp)
	cfg.Interface.PreDown = nonNilStrings(cfg.Interface.PreDown)
	cfg.Interface.PostDown = nonNilStrings(cfg.Interface.PostDown)
	for i := range cfg.Peers {
		cfg.Peers[i].AllowedIPs = nonNilStrings(cfg.Peers[i].AllowedIPs)
	}
	return cfg, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func applyKV(dst any, key, val string) error {
	switch d := dst.(type) {
	case *Interface:
		switch key {
		case "privatekey":
			if err := ValidateKey(val); err != nil {
				return fmt.Errorf("PrivateKey: %w", err)
			}
			d.PrivateKey = val
		case "listenport":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 65535 {
				return fmt.Errorf("ListenPort must be an integer between 0 and 65535")
			}
			d.ListenPort = n
		case "fwmark":
			d.FwMark = val
		case "address":
			v, err := appendCSV(d.Address, val, validateIPPrefix)
			if err != nil {
				return fmt.Errorf("Address: %w", err)
			}
			d.Address = v
		case "dns":
			v, err := appendCSV(d.DNS, val, nil)
			if err != nil {
				return err
			}
			d.DNS = v
		case "mtu":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 65535 {
				return fmt.Errorf("MTU must be an integer between 0 and 65535")
			}
			d.MTU = n
		case "table":
			d.Table = val
		case "preup":
			d.PreUp = append(d.PreUp, val)
		case "postup":
			d.PostUp = append(d.PostUp, val)
		case "predown":
			d.PreDown = append(d.PreDown, val)
		case "postdown":
			d.PostDown = append(d.PostDown, val)
		case "saveconfig":
			if !strings.EqualFold(val, "false") {
				return fmt.Errorf("SaveConfig must be false; runtime state must not be written to disk")
			}
		}
	case *Peer:
		switch key {
		case "publickey":
			if err := ValidateKey(val); err != nil {
				return fmt.Errorf("PublicKey: %w", err)
			}
			d.PublicKey = val
		case "presharedkey":
			if err := ValidateKey(val); err != nil {
				return fmt.Errorf("PresharedKey: %w", err)
			}
			d.PresharedKey = val
		case "allowedips":
			v, err := appendCSV(d.AllowedIPs, val, validateIPPrefix)
			if err != nil {
				return fmt.Errorf("AllowedIPs: %w", err)
			}
			d.AllowedIPs = v
		case "endpoint":
			d.Endpoint = val
		case "persistentkeepalive":
			if strings.EqualFold(val, "off") {
				d.PersistentKeepalive = -1
				return nil
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 65535 {
				return fmt.Errorf("PersistentKeepalive must be off or an integer between 0 and 65535")
			}
			d.PersistentKeepalive = n
		}
	}
	return nil
}

func appendCSV(dst []string, val string, check func(string) error) ([]string, error) {
	for _, part := range strings.Split(val, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if check != nil {
			if err := check(s); err != nil {
				return dst, err
			}
		}
		dst = append(dst, s)
	}
	return dst, nil
}

// ValidateKey checks that v is a valid WireGuard key: base64 of 32 bytes.
func ValidateKey(v string) error {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return fmt.Errorf("not valid base64")
	}
	if len(b) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	if base64.StdEncoding.EncodeToString(b) != v {
		return fmt.Errorf("key must be canonical base64 without whitespace")
	}
	return nil
}

func validateIPPrefix(s string) error {
	if !strings.Contains(s, "/") {
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("invalid IP address")
		}
		return nil
	}
	if _, err := netip.ParsePrefix(s); err != nil {
		return fmt.Errorf("invalid CIDR")
	}
	return nil
}

// UpsertPeer adds p or replaces the existing peer with the same PublicKey.
func (c *Config) UpsertPeer(p Peer) {
	for i := range c.Peers {
		if c.Peers[i].PublicKey == p.PublicKey {
			c.Peers[i] = p
			return
		}
	}
	c.Peers = append(c.Peers, p)
}

// RemovePeer deletes the peer with the given public key;
// returns false when no such peer exists.
func (c *Config) RemovePeer(publicKey string) bool {
	for i := range c.Peers {
		if c.Peers[i].PublicKey == publicKey {
			c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
			return true
		}
	}
	return false
}

// Render produces canonical configuration text.
func (c *Config) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	i := c.Interface
	if i.PrivateKey != "" {
		fmt.Fprintf(&b, "PrivateKey = %s\n", i.PrivateKey)
	}
	if i.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", i.ListenPort)
	}
	if i.FwMark != "" {
		fmt.Fprintf(&b, "FwMark = %s\n", i.FwMark)
	}
	if len(i.Address) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(i.Address, ", "))
	}
	if len(i.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(i.DNS, ", "))
	}
	if i.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", i.MTU)
	}
	if i.Table != "" {
		fmt.Fprintf(&b, "Table = %s\n", i.Table)
	}
	writeHooks(&b, "PreUp", i.PreUp)
	writeHooks(&b, "PostUp", i.PostUp)
	writeHooks(&b, "PreDown", i.PreDown)
	writeHooks(&b, "PostDown", i.PostDown)
	if i.SaveConfig {
		b.WriteString("SaveConfig = true\n")
	}
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

func writeHooks(b *strings.Builder, name string, cmds []string) {
	for _, c := range cmds {
		fmt.Fprintf(b, "%s = %s\n", name, c)
	}
}
