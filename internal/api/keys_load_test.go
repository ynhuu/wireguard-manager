package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

type keySyncRunner struct {
	*wg.DemoRunner
	calls []string
	fail  bool
}

func (r *keySyncRunner) SyncConf(iface string) error {
	r.calls = append(r.calls, iface)
	if r.fail {
		return errors.New("sync failed")
	}
	return nil
}

func (r *keySyncRunner) ShowAllDump() (string, error) {
	dump, err := r.DemoRunner.ShowAllDump()
	return strings.ReplaceAll(dump, "wg0\t", "wg1\t"), err
}

func TestKeyLoadUnloadRetainsVault(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = dir
	path := filepath.Join(dir, "wg1.conf")
	content := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.3/32\n", testPubKeys[0], testPubKeys[2])
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := &store.VaultEntry{ID: "phone", Name: "phone", Iface: "wg1", PublicKey: testPubKeys[1], Address: []string{"10.0.0.2/32"}}
	if err := st.SaveVault([]*store.VaultEntry{entry}); err != nil {
		t.Fatal(err)
	}
	runner := &keySyncRunner{DemoRunner: wg.NewDemoRunner()}
	srv := New(cfg, st, runner, true)
	sess, err := srv.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	router := srv.Router()
	do := func(method, url, body string) map[string]json.RawMessage {
		t.Helper()
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, url, w.Code, w.Body.String())
		}
		var resp map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	checkLoaded := func(want bool) {
		t.Helper()
		resp := do("GET", "/api/keys", "")
		var entries []keyView
		if err := json.Unmarshal(resp["entries"], &entries); err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Loaded != want {
			t.Fatalf("unexpected vault state: %s", resp["entries"])
		}
	}
	checkLoaded(false)
	resp := do("POST", "/api/keys/phone/deploy", `{"apply_runtime":true}`)
	if string(resp["applied"]) != "true" {
		t.Fatalf("load not applied: %v", resp)
	}
	checkLoaded(true)
	runner.fail = true
	resp = do("POST", "/api/keys/phone/unload", `{}`)
	if string(resp["config_removed"]) != "true" || resp["apply_error"] == nil {
		t.Fatalf("expected on-disk removal and runtime error: %v", resp)
	}
	checkLoaded(false)
	runner.fail = false
	resp = do("POST", "/api/keys/phone/unload", `{}`)
	if string(resp["applied"]) != "true" || len(runner.calls) != 3 {
		t.Fatalf("unload retry did not synchronize: %v calls=%v", resp, runner.calls)
	}
	for _, iface := range runner.calls {
		if iface != "wg1" {
			t.Fatalf("wrong interface: %s", iface)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Peers) != 1 || conf.Peers[0].PublicKey != testPubKeys[2] || len(conf.Interface.Address) != 1 {
		t.Fatalf("unrelated configuration changed: %+v", conf)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("missing backup: %v", err)
	}
	entries, err := st.LoadVault()
	if err != nil || len(entries) != 1 || entries[0].PublicKey != entry.PublicKey {
		t.Fatalf("vault entry lost: %v %v", entries, err)
	}
}
