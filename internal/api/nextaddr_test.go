package api

import (
	"net/netip"
	"strconv"
	"testing"
)

func TestNextFreeHost(t *testing.T) {
	mustPrefix := func(s string) netip.Prefix {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		return p.Masked()
	}

	sn := mustPrefix("10.10.0.1/24")
	used := []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.10.0.1"), 32)}

	got := nextFreeHost(sn, used)
	if got != netip.MustParseAddr("10.10.0.2") {
		t.Fatalf("want 10.10.0.2, got %v", got)
	}

	// fill a gap and verify it is skipped
	used = append(used,
		netip.PrefixFrom(netip.MustParseAddr("10.10.0.2"), 32),
		netip.PrefixFrom(netip.MustParseAddr("10.10.0.3"), 32),
	)
	if got := nextFreeHost(sn, used); got != netip.MustParseAddr("10.10.0.4") {
		t.Fatalf("want 10.10.0.4, got %v", got)
	}

	// exhausted subnet returns invalid addr
	for i := 2; i < 255; i++ {
		used = append(used, netip.PrefixFrom(netip.MustParseAddr("10.10.0."+strconv.Itoa(i)), 32))
	}
	if got := nextFreeHost(mustPrefix("10.10.0.1/24"), used); got.IsValid() {
		t.Fatalf("expected no free host, got %v", got)
	}

	// ipv6
	sn6 := mustPrefix("fd00::1/64")
	used6 := []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("fd00::1"), 128)}
	if got := nextFreeHost(sn6, used6); got != netip.MustParseAddr("fd00::2") {
		t.Fatalf("want fd00::2, got %v", got)
	}
}

func TestNextFreeHostSkipsReservedPrefix(t *testing.T) {
	used := []netip.Prefix{
		netip.PrefixFrom(netip.MustParseAddr("10.10.0.1"), 32),
		netip.MustParsePrefix("10.10.0.4/30"),
	}
	if got := nextFreeHost(netip.MustParsePrefix("10.10.0.1/24"), used); got != netip.MustParseAddr("10.10.0.2") {
		t.Fatalf("want 10.10.0.2, got %v", got)
	}
	used = append(used, netip.PrefixFrom(netip.MustParseAddr("10.10.0.2"), 32), netip.PrefixFrom(netip.MustParseAddr("10.10.0.3"), 32))
	if got := nextFreeHost(netip.MustParsePrefix("10.10.0.1/24"), used); got != netip.MustParseAddr("10.10.0.8") {
		t.Fatalf("want first address outside reserved prefix, got %v", got)
	}
}

func TestNextFreeHostJumpsPastLargeReservedPrefix(t *testing.T) {
	used := []netip.Prefix{
		netip.MustParsePrefix("10.10.0.0/18"),
	}
	got := nextFreeHost(netip.MustParsePrefix("10.10.0.1/16"), used)
	if want := netip.MustParseAddr("10.10.64.0"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestEndpointWithPort(t *testing.T) {
	cases := map[string]string{
		"vpn.example.com:51820": "vpn.example.com:51821",
		"vpn.example.com":       "vpn.example.com:51821",
		"[2001:db8::1]:51820":   "[2001:db8::1]:51821",
		"2001:db8::1":           "[2001:db8::1]:51821",
		"":                      "",
	}
	for input, want := range cases {
		if got := endpointWithPort(input, 51821); got != want {
			t.Errorf("endpointWithPort(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValidateEndpointHost(t *testing.T) {
	cases := map[string]bool{
		"":                        false,
		"vpn.example.com":         false,
		"203.0.113.10":            false,
		"2001:db8::10":            false,
		"vpn.example.com:51820":   true,
		"[2001:db8::10]":          true,
		"https://vpn.example.com": true,
	}
	for input, wantErr := range cases {
		if gotErr := validateEndpointHost(input) != nil; gotErr != wantErr {
			t.Errorf("validateEndpointHost(%q) error = %v, want %v", input, gotErr, wantErr)
		}
	}
}
