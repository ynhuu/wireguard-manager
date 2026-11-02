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

	appconf "github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

// quickDownFailRunner simulates wg-quick down failing (e.g. interface not
// running) while up keeps working, to prove restart still brings the
// interface back.
type quickDownFailRunner struct{ *wg.DemoRunner }

func (r *quickDownFailRunner) QuickDown(iface string) error { return errors.New("not running") }

// TestVaultNoDeadlockOnDuplicate is a regression test for the mutex leak in
// handleKeyCreate: a 409 response used to return while still holding the
// vault lock, deadlocking every later vault operation.
// testPubKeys 是合法的 32 字节 base64 公钥，供创建类用例使用。
var testPubKeys = []string{
	"qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM=",
	"Wb1l0n8QeB4sJ7FjrbOtOFPLIBo3rSCmRFy9vFbcRTA=",
	"Lp2XUUzCvzuPQhKnWm6i3q0lTtH0sJ1cE9DkGvAaRxM=",
	"9lRfF4aS0DpVj7TQmXcZ2bYhUoN1eKwLrP5gJ8vCxHs=",
	"kiIeVuaa7V4+fFdx8gh+m1lZHc0Bfsj4pPsLSD8oOjg=",
}

// Run with -timeout to catch hangs.
func TestVaultNoDeadlockOnDuplicate(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	srv := New(cfg, st, wg.NewDemoRunner(), true)
	router := srv.Router()

	sess, err := srv.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"a","public_key":%q}`, testPubKeys[0])).Code; c != http.StatusOK {
		t.Fatalf("first create: got %d", c)
	}
	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"a","public_key":%q}`, testPubKeys[0])).Code; c != http.StatusConflict {
		t.Fatalf("duplicate create: got %d want 409", c)
	}
	// 409 之后的任何 vault 操作都必须正常响应（旧实现会死锁挂起）
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"name":"b%d","public_key":%q}`, i, testPubKeys[i+1])
		if c := do("POST", "/api/keys", body).Code; c != http.StatusOK {
			t.Fatalf("create after conflict (#%d): got %d — vault lock leaked?", i, c)
		}
	}
	if c := do("GET", "/api/keys", "").Code; c != http.StatusOK {
		t.Fatalf("list after conflict: got %d", c)
	}
}

// TestVaultNoDeadlockOnUpdateMissing covers early-return paths of other
// handlers that previously ran between lock and unlock.
func TestVaultNoDeadlockOnUpdateMissing(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	srv := New(cfg, st, wg.NewDemoRunner(), true)
	router := srv.Router()

	sess, _ := srv.sess.NewSession("tester")
	do := func(method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if c := do("PUT", `/api/keys/missing`, `{"name":"x"}`).Code; c != http.StatusNotFound {
		t.Fatalf("update missing: got %d want 404", c)
	}
	if c := do("DELETE", `/api/keys/missing`, ``).Code; c != http.StatusNotFound {
		t.Fatalf("delete missing: got %d want 404", c)
	}
	// 锁必须仍可用
	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"ok","public_key":%q}`, testPubKeys[0])).Code; c != http.StatusOK {
		t.Fatalf("create after 404s: got %d — vault lock leaked?", c)
	}
}

// TestKeyCreateEndpointFallsBackToDefault covers the empty server_endpoint
// path of handleKeyCreate: it must inherit cfg.Defaults.ServerEndpoint so
// the generated client config is not missing the Endpoint line.
func TestKeyCreateEndpointFallsBackToDefault(t *testing.T) {
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
	confPath := filepath.Join(cfg.WG.ConfDir, "wg0.conf")
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51820\nAddress = 10.0.0.1/24\n", testPubKeys[0])
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st, wg.NewDemoRunner(), true)
	router := srv.Router()

	sess, _ := srv.sess.NewSession("tester")
	do := func(method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"p1","public_key":%q}`, testPubKeys[1])).Code; c != http.StatusOK {
		t.Fatalf("create: got %d", c)
	}
	resp := do("GET", "/api/keys", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("list: got %d", resp.Code)
	}
	body := resp.Body.String()
	if !strings.Contains(body, `"server_endpoint":"vpn.example.com:51820"`) {
		t.Fatalf("expected fallback endpoint in list, got: %s", body)
	}

	// 显式传入的 Endpoint 不被默认值覆盖
	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"p2","public_key":%q,"server_endpoint":"other.host:9999"}`, testPubKeys[2])).Code; c != http.StatusOK {
		t.Fatalf("create explicit: got %d", c)
	}
	if body := do("GET", "/api/keys", "").Body.String(); !strings.Contains(body, `"server_endpoint":"other.host:9999"`) {
		t.Fatalf("explicit endpoint lost: %s", body)
	}

	withoutPort := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.1/24\n", testPubKeys[0])
	if err := os.WriteFile(confPath, []byte(withoutPort), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"p3","public_key":%q}`, testPubKeys[3])).Code; c != http.StatusBadRequest {
		t.Fatalf("create without ListenPort: got %d want 400", c)
	}
}

// TestQuickRestartAction locks the /api/wg/quick contract for the restart
// action added because the UI 重启 button previously issued a plain "up",
// which always fails on a running interface.
func TestQuickRestartAction(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	srv := New(cfg, st, wg.NewDemoRunner(), true)
	router := srv.Router()

	sess, _ := srv.sess.NewSession("tester")
	do := func(body string) int {
		req := httptest.NewRequest("POST", "/api/wg/quick", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if c := do(`{"iface":"wg0","action":"restart"}`); c != http.StatusOK {
		t.Fatalf("restart: got %d want 200", c)
	}
	if c := do(`{"iface":"wg0","action":"reboot"}`); c != http.StatusBadRequest {
		t.Fatalf("invalid action: got %d want 400", c)
	}
}

// TestQuickRestartToleratesDownFailure proves the restart branch ignores a
// failed down (already-stopped interface) and still runs up.
func TestQuickRestartToleratesDownFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	srv := New(cfg, st, &quickDownFailRunner{wg.NewDemoRunner()}, true)
	router := srv.Router()

	sess, _ := srv.sess.NewSession("tester")
	req := httptest.NewRequest("POST", "/api/wg/quick", strings.NewReader(`{"iface":"wg0","action":"restart"}`))
	req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
	req.Header.Set("X-CSRF-Token", sess.CSRF)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("restart with failing down: got %d want 200 (up must still run)", w.Code)
	}
}

// TestKeyUpdateKeepaliveOmittedStays locks the pointer semantics of
// keyUpdateReq.Keepalive: a PUT without the field must keep the stored
// value (the old int-based version silently zeroed it), while an explicit
// value — including 0 (= off) — applies.
func TestKeyUpdateKeepaliveOmittedStays(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := appconf.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	srv := New(cfg, st, wg.NewDemoRunner(), true)
	router := srv.Router()

	sess, _ := srv.sess.NewSession("tester")
	do := func(method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "wgm_session", Value: sess.Token})
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	if c := do("POST", "/api/keys", fmt.Sprintf(`{"name":"p1","public_key":%q,"keepalive":25}`, testPubKeys[3])).Code; c != http.StatusOK {
		t.Fatalf("create: got %d", c)
	}
	id := ""
	for _, e := range mustEntries(t, do("GET", "/api/keys", "")) {
		id = e.ID
	}
	// 省略 keepalive 字段：保持 25 不变
	if c := do("PUT", "/api/keys/"+id, `{"name":"p1-renamed"}`).Code; c != http.StatusOK {
		t.Fatalf("update omitted: got %d", c)
	}
	if got := findKeepalive(t, do("GET", "/api/keys", ""), id); got != 25 {
		t.Fatalf("omitted keepalive: got %d want 25 (must not zero)", got)
	}
	// 显式 0：关闭 keepalive
	if c := do("PUT", "/api/keys/"+id, `{"keepalive":0}`).Code; c != http.StatusOK {
		t.Fatalf("update zero: got %d", c)
	}
	if got := findKeepalive(t, do("GET", "/api/keys", ""), id); got != 0 {
		t.Fatalf("explicit keepalive 0: got %d want 0", got)
	}
}

func mustEntries(t *testing.T, resp *httptest.ResponseRecorder) []*store.VaultEntry {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("list keys: got %d body %s", resp.Code, resp.Body.String())
	}
	var out struct {
		Entries []*store.VaultEntry `json:"entries"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return out.Entries
}

func findKeepalive(t *testing.T, resp *httptest.ResponseRecorder, id string) int {
	t.Helper()
	for _, e := range mustEntries(t, resp) {
		if e.ID == id {
			return e.Keepalive
		}
	}
	t.Fatalf("entry %s not found in list", id)
	return -1
}
