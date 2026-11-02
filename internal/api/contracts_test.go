package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconf "github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

func TestKeyDeleteDefaultsToEntryIface(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	if err := os.MkdirAll(cfg.WG.ConfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	peerKey := testPubKeys[4]
	content := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51820\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", testPubKeys[0], peerKey)
	for _, iface := range []string{"wg0", "wg1"} {
		if err := os.WriteFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveVault([]*store.VaultEntry{{
		ID:        "entry-1",
		Name:      "phone",
		PublicKey: peerKey,
		Iface:     "wg1",
	}}); err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, st, wg.NewDemoRunner(), true)
	sess, err := srv.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("DELETE", "/api/keys/entry-1", nil)
	req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
	req.Header.Set("X-CSRF-Token", sess.CSRF)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: got %d body %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if removed, ok := resp["config_removed"].(bool); !ok || !removed {
		t.Fatalf("expected peer removal from entry iface, got %s", w.Body.String())
	}

	for _, tc := range []struct {
		iface       string
		expectPeers int
	}{
		{iface: "wg0", expectPeers: 1},
		{iface: "wg1", expectPeers: 0},
	} {
		raw, err := os.ReadFile(filepath.Join(cfg.WG.ConfDir, tc.iface+".conf"))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := appconf.Parse(string(raw))
		if err != nil {
			t.Fatalf("parse %s: %v", tc.iface, err)
		}
		if got := len(parsed.Peers); got != tc.expectPeers {
			t.Fatalf("%s peers: got %d want %d", tc.iface, got, tc.expectPeers)
		}
	}
}

func TestKeyUpdateIfaceRecomputesEndpoint(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	cfg.Defaults.ServerEndpoint = "vpn.example.com"
	if err := os.MkdirAll(cfg.WG.ConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for iface, port := range map[string]int{"wg0": 51820, "wg1": 51821} {
		content := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\nAddress = 10.0.0.1/24\n", testPubKeys[0], port)
		if err := os.WriteFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveVault([]*store.VaultEntry{{
		ID:             "entry-1",
		Name:           "phone",
		Iface:          "wg0",
		PublicKey:      testPubKeys[4], // not loaded by DemoRunner
		ServerEndpoint: "vpn.example.com:51820",
	}}); err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, st, wg.NewDemoRunner(), true)
	sess, err := srv.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "/api/keys/entry-1", strings.NewReader(`{"iface":"wg1"}`))
	req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
	req.Header.Set("X-CSRF-Token", sess.CSRF)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update: got %d body %s", w.Code, w.Body.String())
	}

	entries, err := st.LoadVault()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Iface != "wg1" || entries[0].ServerEndpoint != "vpn.example.com:51821" {
		t.Fatalf("unexpected updated entry: %+v", entries)
	}
}

func TestSanitizeDownloadNamePreservesUnicode(t *testing.T) {
	if got := sanitizeDownloadName("手机"); got != "手机" {
		t.Fatalf("unicode name: got %q want %q", got, "手机")
	}
	if got := sanitizeDownloadName("手机/1"); got != "手机_1" {
		t.Fatalf("unsafe unicode name: got %q want %q", got, "手机_1")
	}
}

func TestConfCreateRejectsExistingFile(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	if err := os.MkdirAll(cfg.WG.ConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.WG.ConfDir, "wg0.conf")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, st, wg.NewDemoRunner(), true)
	sess, err := srv.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("PUT", "/api/conf/write", strings.NewReader(`{"file":"wg0.conf","content":"[Interface]\n","create":true}`))
	req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
	req.Header.Set("X-CSRF-Token", sess.CSRF)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("create existing file: got %d body %s", w.Code, w.Body.String())
	}
	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(raw) != "existing" {
		t.Fatalf("existing config was changed: %q", string(raw))
	}
}

func TestBackupFileEnforcesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".bak", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := backupFile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("backup permissions = %04o, want 0600", got)
	}
}
