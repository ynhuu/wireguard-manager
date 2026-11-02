package config

import (
	"strings"
	"testing"
)

const sampleConf = `# server config
[Interface]
PrivateKey = 6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o=
Address = 10.10.0.1/24, fd00::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=
AllowedIPs = 10.10.0.2/32
Endpoint = 203.0.113.7:41234
PersistentKeepalive = 25

[Peer]
PublicKey = Wb1l0n8QeB4sJ7FjrbOtOFPLIBo3rSCmRFy9vFbcRTA=
PresharedKey = 9lRfF4aS0DpVj7TQmXcZ2bYhUoN1eKwLrP5gJ8vCxHs=
AllowedIPs = 10.10.0.3/32
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse(sampleConf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	i := cfg.Interface
	if i.PrivateKey == "" || i.ListenPort != 51820 {
		t.Errorf("interface mismatch: %+v", i)
	}
	if len(i.Address) != 2 || i.Address[0] != "10.10.0.1/24" {
		t.Errorf("address = %v", i.Address)
	}
	if len(i.PostUp) != 1 {
		t.Errorf("postup = %v", i.PostUp)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(cfg.Peers))
	}
	p := cfg.Peers[0]
	if p.PersistentKeepalive != 25 || p.Endpoint != "203.0.113.7:41234" {
		t.Errorf("peer0 mismatch: %+v", p)
	}
	if cfg.Peers[1].PresharedKey == "" {
		t.Error("peer1 psk missing")
	}
}

func TestRenderRoundTrip(t *testing.T) {
	cfg, err := Parse(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	rendered := cfg.Render()
	cfg2, err := Parse(rendered)
	if err != nil {
		t.Fatalf("re-parse rendered: %v\nrendered:\n%s", err, rendered)
	}
	if cfg.Interface.ListenPort != cfg2.Interface.ListenPort ||
		len(cfg.Peers) != len(cfg2.Peers) ||
		cfg.Peers[0].PublicKey != cfg2.Peers[0].PublicKey {
		t.Errorf("round trip mismatch")
	}
}

func TestRejectInvalid(t *testing.T) {
	cases := map[string]string{
		"no interface":     "[Peer]\nPublicKey = qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=\n",
		"bad key":          "[Interface]\nPrivateKey = short=\n",
		"bad port":         "[Interface]\nListenPort = 99999\n",
		"bad cidr":         "[Interface]\nAddress = 999.1.1.1/24\n",
		"peer no pubkey":   "[Interface]\nPrivateKey = 6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o=\n[Peer]\nAllowedIPs = 10.0.0.2/32\n",
		"unknown key":      "[Interface]\nBogus = 1\n",
		"key before sect":  "PrivateKey = abc\n",
		"no privkey+peers": "[Interface]\nListenPort = 51820\n[Peer]\nPublicKey = qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=\n",
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}

func TestKeepaliveOff(t *testing.T) {
	cfg, err := Parse("[Interface]\nPrivateKey = 6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o=\n[Peer]\nPublicKey = qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=\nPersistentKeepalive = off\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers[0].PersistentKeepalive != -1 {
		t.Errorf("want -1 for off, got %d", cfg.Peers[0].PersistentKeepalive)
	}
}

func TestValidateKeyRejectsEmbeddedNewlines(t *testing.T) {
	key := "6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o="
	if err := ValidateKey(key[:20] + "\n" + key[20:]); err == nil {
		t.Fatal("multiline key would break generated configuration")
	}
}

func TestParseErrorDoesNotEchoRawConfigSecrets(t *testing.T) {
	secret := "sensitive-private-key"
	for _, raw := range []string{secret, secret + " = value", "[" + secret + "]", "ListenPort = " + secret, "MTU = " + secret, "Address = " + secret} {
		_, err := Parse("[Interface]\n" + raw + "\n")
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatal("parse error echoed raw secret material")
		}
	}
}
