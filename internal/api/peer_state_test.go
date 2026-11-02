package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yq/wireguard-manager/internal/store"
)

func TestKeyListDistinguishesConfigAndRuntimeStates(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf()+"\n[Peer]\nPublicKey = "+testPubKeys[1]+"\n")
	h.r.dump = securityDump(false)
	if err := os.WriteFile(filepath.Join(h.s.cfg.WG.ConfDir, "broken.conf"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	entries := []*store.VaultEntry{
		{ID: "configured", Iface: "wg0", PublicKey: testPubKeys[1]},
		{ID: "absent", Iface: "wg0", PublicKey: testPubKeys[2]},
		{ID: "stopped", Iface: "wg1", PublicKey: testPubKeys[1]},
		{ID: "broken-1", Iface: "broken", PublicKey: testPubKeys[1]},
		{ID: "broken-2", Iface: "broken", PublicKey: testPubKeys[2]},
	}
	if err := h.st.SaveVault(entries); err != nil {
		t.Fatal(err)
	}
	list := func() []keyView {
		t.Helper()
		w := h.do("GET", "/api/keys", "")
		var response struct {
			Entries []keyView `json:"entries"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Entries) != len(entries) {
			t.Fatalf("invalid list response: %s", w.Body.String())
		}
		return response.Entries
	}
	items := list()
	if !items[0].Loaded || !items[0].NeedsApply || items[0].RuntimeLoaded == nil || *items[0].RuntimeLoaded {
		t.Fatal("configured peer on running interface should need application")
	}
	for _, i := range []int{1, 2} {
		if items[i].Loaded || items[i].NeedsApply || items[i].RuntimeLoaded == nil || *items[i].RuntimeLoaded {
			t.Fatal("absent peer reported loaded")
		}
	}
	if items[3].ConfigError == "" || items[3].ConfigError != items[4].ConfigError {
		t.Fatal("shared config error not propagated to every entry")
	}
	// Cached state is request-local; external edits and WG errors must be
	// visible on the next refresh rather than reusing a stale snapshot.
	h.writeConf(t, securityConf())
	h.r.queryErr = errors.New("WG unavailable")
	items = list()
	if items[0].Loaded || items[0].NeedsApply || items[0].RuntimeLoaded != nil || items[0].RuntimeError == "" {
		t.Fatal("new request reused stale file/runtime state")
	}
}

func TestKeyListMissingConfigStillReportsRuntimePeer(t *testing.T) {
	h := newSecurityHarness(t)
	h.savePeer(t)
	h.r.dump = securityDump(true)
	w := h.do("GET", "/api/keys", "")
	var response struct {
		Entries []keyView `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) != 1 {
		t.Fatal("missing vault entry")
	}
	e := response.Entries[0]
	if e.Loaded || !e.NeedsApply || e.RuntimeLoaded == nil || !*e.RuntimeLoaded || e.ConfigError != "" {
		t.Fatal("runtime-only peer state lost")
	}
}
