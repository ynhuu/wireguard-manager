package wg

import (
	"strings"
	"testing"
	"time"
)

const allDump = `wg0	6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o=	kiIeVuaa7V4+fFdx8gh+m1lZHc0Bfsj4pPsLSD8oOjg=	51820	off
wg0	qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=	off	203.0.113.7:41234	10.10.0.2/32,fd00::2/128	1699999999	104857600	524288000	25
wg0	Wb1l0n8QeB4sJ7FjrbOtOFPLIBo3rSCmRFy9vFbcRTA=	9lRfF4aS0DpVj7TQmXcZ2bYhUoN1eKwLrP5gJ8vCxHs=	(none)	10.10.0.3/32	0	0	0	off
wg1	(hidden)	rW+yUKxnIMSqTrxomjKcaZwesf66ZMWfHWlqfGGgPUw=	12345	0x1234
`

func TestParseShowAllDump(t *testing.T) {
	ifaces, err := ParseDump(allDump)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(ifaces))
	}
	wg0 := ifaces[0]
	if wg0.Name != "wg0" || wg0.ListenPort != 51820 || wg0.FwMark != 0 {
		t.Errorf("wg0 header mismatch: %+v", wg0)
	}
	if wg0.PublicKey == "" {
		t.Error("public key not derived from private key")
	}
	if len(wg0.Peers) != 2 {
		t.Fatalf("want 2 peers on wg0, got %d", len(wg0.Peers))
	}
	p1 := wg0.Peers[0]
	if p1.PresharedKeySet {
		t.Error("peer1 should have no psk")
	}
	if p1.Endpoint != "203.0.113.7:41234" {
		t.Errorf("endpoint = %q", p1.Endpoint)
	}
	if len(p1.AllowedIPs) != 2 || p1.AllowedIPs[1] != "fd00::2/128" {
		t.Errorf("allowed-ips = %v", p1.AllowedIPs)
	}
	want := time.Unix(1699999999, 0)
	if !p1.LatestHandshake.Equal(want) {
		t.Errorf("handshake = %v want %v", p1.LatestHandshake, want)
	}
	if p1.RXBytes != 104857600 || p1.TXBytes != 524288000 {
		t.Errorf("transfer = rx %d tx %d", p1.RXBytes, p1.TXBytes)
	}
	if p1.KeepaliveSeconds != 25 {
		t.Errorf("keepalive = %d", p1.KeepaliveSeconds)
	}
	p2 := wg0.Peers[1]
	if !p2.PresharedKeySet {
		t.Error("peer2 should have psk")
	}
	if !p2.LatestHandshake.IsZero() {
		t.Error("peer2 never handshaked")
	}
	wg1 := ifaces[1]
	if wg1.ListenPort != 12345 || wg1.FwMark != 0x1234 {
		t.Errorf("wg1 header mismatch: %+v", wg1)
	}
	if wg1.PrivateKey == "(hidden)" {
		t.Error("(hidden) must be treated as unset")
	}
	if wg1.PublicKey == "" {
		t.Error("wg1 public key should be parsed even when private key hidden")
	}
}

func TestParseUnprefixedDump(t *testing.T) {
	out := "priv=\tpub=\t51820\toff\npub=\toff\t(none)\t(none)\t0\t0\t0\toff\n"
	ifaces, err := ParseDump(out)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].ListenPort != 51820 {
		t.Fatalf("iface parse failed: %+v", ifaces)
	}
	if ifaces[0].PublicKey != "pub=" {
		t.Errorf("public key = %q", ifaces[0].PublicKey)
	}
	if len(ifaces[0].Peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(ifaces[0].Peers))
	}
}

func TestParseDumpEmptyAllowedIPsIsNonNil(t *testing.T) {
	out := "wg0\tpriv\tpub\t51820\toff\nwg0\tpeer\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"
	ifaces, err := ParseDump(out)
	if err != nil {
		t.Fatal(err)
	}
	if ifaces[0].Peers[0].AllowedIPs == nil {
		t.Fatal("empty allowed_ips must marshal as an empty array")
	}
}

// TestParseRealDeviceOutput uses a line captured from a production device.
func TestParseRealDeviceOutput(t *testing.T) {
	line := "wg0\t2FacOBOPqbLi7N5OKaeQbwZVAWGs4Z6Gf3nREe/nhmE=\trW+yUKxnIMSqTrxomjKcaZwesf66ZMWfHWlqfGGgPUw=\t51830\toff"
	ifaces, err := ParseDump(line)
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	i := ifaces[0]
	if i.Name != "wg0" || i.ListenPort != 51830 || i.FwMark != 0 {
		t.Fatalf("header mismatch: %+v", i)
	}
	if i.PrivateKey != "2FacOBOPqbLi7N5OKaeQbwZVAWGs4Z6Gf3nREe/nhmE=" ||
		i.PublicKey != "rW+yUKxnIMSqTrxomjKcaZwesf66ZMWfHWlqfGGgPUw=" {
		t.Fatalf("keys mismatch: %+v", i)
	}
}

func TestParseEmptyDump(t *testing.T) {
	for _, s := range []string{"", "\n", "\t\n"} {
		if _, err := ParseDump(s); err != nil {
			t.Errorf("empty output should not error, got %v for %q", err, s)
		}
	}
}

func TestParseDumpErrorDoesNotExposeSecrets(t *testing.T) {
	secret := "sensitive-private-key"
	_, err := ParseDump("wg0\t" + secret + "\textra")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("malformed dump exposed raw key material")
	}
}

func TestGenerateAndDeriveKeys(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || priv[43] != '=' {
		t.Fatalf("bad private key format: %q", priv)
	}
	pub := PublicKeyFromPrivate(priv)
	if len(pub) != 44 || pub[43] != '=' {
		t.Fatalf("bad public key format: %q", pub)
	}
	if pub != PublicKeyFromPrivate(priv) {
		t.Error("derivation not deterministic")
	}
	psk, err := GeneratePresharedKey()
	if err != nil || len(psk) != 44 {
		t.Fatalf("bad psk: %q err=%v", psk, err)
	}
	if priv == psk {
		t.Error("psk collided with private key (astronomically unlikely)")
	}
	if PublicKeyFromPrivate("not-base64!!") != "" {
		t.Error("invalid key should yield empty public key")
	}
}
