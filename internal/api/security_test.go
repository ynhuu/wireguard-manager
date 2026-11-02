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
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/yq/wireguard-manager/internal/auth"
	"github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

type securityRunner struct {
	*wg.DemoRunner
	dump                       string
	queryErr, syncErr, downErr error
	syncCalls                  int
	onSync                     func()
}

func (r *securityRunner) ShowAllDump() (string, error) { return r.dump, r.queryErr }
func (r *securityRunner) QuickDown(string) error       { return r.downErr }
func (r *securityRunner) SyncConf(string) error {
	r.syncCalls++
	if r.syncErr == nil && r.onSync != nil {
		r.onSync()
	}
	return r.syncErr
}

type securityHarness struct {
	s       *Server
	st      *store.Store
	r       *securityRunner
	session *auth.Session
	path    string
}

func newSecurityHarness(t *testing.T) *securityHarness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.DataDir = dir
	cfg.WG.ConfDir = filepath.Join(dir, "conf")
	if err := os.Mkdir(cfg.WG.ConfDir, 0700); err != nil {
		t.Fatal(err)
	}
	r := &securityRunner{DemoRunner: wg.NewDemoRunner()}
	s := New(cfg, st, r, true)
	sess, err := s.sess.NewSession("tester")
	if err != nil {
		t.Fatal(err)
	}
	return &securityHarness{s: s, st: st, r: r, session: sess, path: filepath.Join(cfg.WG.ConfDir, "wg0.conf")}
}

func (h *securityHarness) do(method, url, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "wgm_session", Value: h.session.Token})
	req.Header.Set("X-CSRF-Token", h.session.CSRF)
	w := httptest.NewRecorder()
	h.s.Router().ServeHTTP(w, req)
	return w
}

func securityConf() string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51820\nAddress = 10.0.0.1/24\n", testPubKeys[0])
}

func securityDump(peer bool) string {
	out := fmt.Sprintf("wg0\t%s\t%s\t51820\toff\n", testPubKeys[0], testPubKeys[4])
	if peer {
		out += fmt.Sprintf("wg0\t%s\t(none)\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n", testPubKeys[1])
	}
	return out
}

func (h *securityHarness) writeConf(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func (h *securityHarness) savePeer(t *testing.T) *store.VaultEntry {
	t.Helper()
	e := &store.VaultEntry{ID: "phone", Name: "phone", Iface: "wg0", PublicKey: testPubKeys[1], Address: []string{"10.0.0.2/32"}}
	if err := h.st.SaveVault([]*store.VaultEntry{e}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (h *securityHarness) saveUser(t *testing.T, enabled bool) *store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("old-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Username: "tester", PasswordHash: string(hash), TOTPSecret: "JBSWY3DPEHPK3PXP", TOTPEnabled: enabled}
	if err := h.st.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestClientConfigExportsStoredPSK(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.savePeer(t)
	var err error
	e.PrivateKeyEnc, err = h.st.Encrypt([]byte(testPubKeys[0]))
	if err != nil {
		t.Fatal(err)
	}
	e.PresharedKeyEnc, err = h.st.Encrypt([]byte(testPubKeys[2]))
	if err != nil {
		t.Fatal(err)
	}
	e.ServerPubKey = testPubKeys[4]
	if err := h.st.SaveVault([]*store.VaultEntry{e}); err != nil {
		t.Fatal(err)
	}
	w := h.do("GET", "/api/keys/phone/client-config", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "PresharedKey = "+testPubKeys[2]) || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("export omitted PSK")
	}
	w = h.do("GET", "/api/keys/phone/qrcode", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("QR export failed")
	}
}

func TestConfigReadRedactsPrivateKeyAndWriteRestoresIt(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())

	w := h.do("GET", "/api/conf/read?file=wg0.conf", "")
	if w.Code != http.StatusOK {
		t.Fatalf("read failed: %d %s", w.Code, w.Body.String())
	}
	var read confReadResp
	if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read.Content, testPubKeys[0]) || !strings.Contains(read.Content, redactedPrivateKeyLine) {
		t.Fatalf("private key leaked or marker missing: %q", read.Content)
	}
	if read.Parsed == nil || read.Parsed.Interface.PrivateKey != "" {
		t.Fatal("parsed response exposed the server private key")
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("config response is cacheable")
	}

	body, err := json.Marshal(confWriteReq{File: "wg0.conf", Content: read.Content, Revision: &read.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if w := h.do("PUT", "/api/conf/write", string(body)); w.Code != http.StatusOK {
		t.Fatalf("redacted config save failed: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PrivateKey = "+testPubKeys[0]) {
		t.Fatal("unchanged redacted editor save lost the server private key")
	}
}

func TestDeploymentValidatesBeforeBackupOrWrite(t *testing.T) {
	for _, field := range []string{"address", "dns", "psk", "public_key"} {
		t.Run(field, func(t *testing.T) {
			h := newSecurityHarness(t)
			h.writeConf(t, securityConf())
			e := h.savePeer(t)
			switch field {
			case "address":
				e.Address = []string{"not-an-ip"}
			case "dns":
				e.DNS = []string{"1.1.1.1\nPostUp = bad"}
			case "psk":
				e.PresharedKeyEnc = "broken-ciphertext"
			case "public_key":
				e.PublicKey = "not-a-key"
			}
			resp := h.s.deployEntryToConfig(e, &deployOpt{ApplyRuntime: true})
			if resp["error"] == nil || resp["written"] != nil || h.r.syncCalls != 0 {
				t.Fatalf("invalid deployment accepted: %v", resp)
			}
			raw, err := os.ReadFile(h.path)
			if err != nil || string(raw) != securityConf() {
				t.Fatal("original config changed")
			}
			if _, err := os.Stat(h.path + ".bak"); !os.IsNotExist(err) {
				t.Fatal("backup changed before validation")
			}
		})
	}
	// The API must reject invalid values before they reach the vault as well.
	h := newSecurityHarness(t)
	w := h.do("POST", "/api/keys", fmt.Sprintf(`{"name":"bad","public_key":%q,"address":["bad"]}`, testPubKeys[1]))
	if w.Code != 400 {
		t.Fatalf("invalid address persisted: %d", w.Code)
	}
}

func TestCreateRejectsMismatchedKeyPair(t *testing.T) {
	h := newSecurityHarness(t)
	privateKey, err := wg.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"name":"mismatch","public_key":%q,"private_key":%q}`, testPubKeys[1], privateKey)
	if w := h.do("POST", "/api/keys", body); w.Code != http.StatusBadRequest {
		t.Fatalf("mismatched key pair accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestRuntimeAddressesAreReserved(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	h.r.dump = securityDump(true)
	w := h.do("GET", "/api/keys/next-address?iface=wg0", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"address":"10.0.0.3/32"`) {
		t.Fatalf("runtime reservation not respected: %d %s", w.Code, w.Body.String())
	}
	body := fmt.Sprintf(`{"name":"conflict","public_key":%q,"address":["10.0.0.2/32"]}`, testPubKeys[2])
	if w := h.do("POST", "/api/keys", body); w.Code != 409 {
		t.Fatalf("runtime collision accepted: %d %s", w.Code, w.Body.String())
	}
	h.r.queryErr = errors.New("unavailable")
	if w := h.do("GET", "/api/keys/next-address?iface=wg0", ""); w.Code != 500 {
		t.Fatal("runtime failure must not return an unchecked suggestion")
	}
}

func TestDeployRechecksAddressOnTargetInterface(t *testing.T) {
	h := newSecurityHarness(t)
	h.savePeer(t)
	path := filepath.Join(h.s.cfg.WG.ConfDir, "wg1.conf")
	content := securityConf() + fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", testPubKeys[2])
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	w := h.do("POST", "/api/keys/phone/deploy", `{"iface":"wg1"}`)
	if !strings.Contains(w.Body.String(), `"error"`) || strings.Contains(w.Body.String(), `"written":true`) {
		t.Fatalf("conflicting deployment accepted: %s", w.Body.String())
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != content {
		t.Fatal("rejected deployment changed target config")
	}
}

func TestConcurrentConfigAndVaultReservation(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	content := securityConf() + fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", testPubKeys[2])
	configBody, _ := json.Marshal(confWriteReq{File: "wg0.conf", Content: content})
	keyBody := fmt.Sprintf(`{"name":"new","public_key":%q,"address":["10.0.0.2/32"]}`, testPubKeys[1])
	var create, editor *httptest.ResponseRecorder
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); create = h.do("POST", "/api/keys", keyBody) }()
	go func() { defer group.Done(); editor = h.do("PUT", "/api/conf/write", string(configBody)) }()
	group.Wait()
	if !((create.Code == 200 && editor.Code == 409) || (create.Code == 409 && editor.Code == 200)) {
		t.Fatalf("expected one reservation winner, got create=%d editor=%d", create.Code, editor.Code)
	}
}

func TestPSKOmissionPreservesAndEmptyClears(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.savePeer(t)
	var err error
	e.PresharedKeyEnc, err = h.st.Encrypt([]byte(testPubKeys[2]))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.st.SaveVault([]*store.VaultEntry{e}); err != nil {
		t.Fatal(err)
	}
	if w := h.do("PUT", "/api/keys/phone", `{}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	entries, _ := h.st.LoadVault()
	if entries[0].PresharedKeyEnc != e.PresharedKeyEnc {
		t.Fatal("omission cleared PSK")
	}
	if w := h.do("PUT", "/api/keys/phone", `{"preshared_key":""}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	entries, _ = h.st.LoadVault()
	if entries[0].PresharedKeyEnc != "" {
		t.Fatal("explicit empty PSK was not cleared")
	}
	h.writeConf(t, securityConf())
	w := h.do("POST", "/api/keys/phone/deploy", `{}`)
	if !strings.Contains(w.Body.String(), `"written":true`) {
		t.Fatal(w.Body.String())
	}
	raw, _ := os.ReadFile(h.path)
	if strings.Contains(string(raw), "PresharedKey") {
		t.Fatal("deployment retained cleared PSK")
	}
}

func TestCreateRejectsOverlappingAddressReservations(t *testing.T) {
	t.Run("vault address", func(t *testing.T) {
		h := newSecurityHarness(t)
		h.savePeer(t)
		body := fmt.Sprintf(`{"name":"second","public_key":%q,"address":["10.0.0.2/32"]}`, testPubKeys[2])
		if w := h.do("POST", "/api/keys", body); w.Code != http.StatusConflict {
			t.Fatalf("duplicate address accepted: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("configured prefix", func(t *testing.T) {
		h := newSecurityHarness(t)
		h.writeConf(t, securityConf()+fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.4/30\n", testPubKeys[4]))
		body := fmt.Sprintf(`{"name":"second","public_key":%q,"address":["10.0.0.6/32"]}`, testPubKeys[2])
		if w := h.do("POST", "/api/keys", body); w.Code != http.StatusConflict {
			t.Fatalf("overlapping address accepted: %d %s", w.Code, w.Body.String())
		}
	})
}

func TestConcurrentPeerCreationCannotReserveSameAddress(t *testing.T) {
	h := newSecurityHarness(t)
	results := make(chan int, 2)
	var group sync.WaitGroup
	for i, key := range []string{testPubKeys[1], testPubKeys[2]} {
		group.Add(1)
		go func(i int, key string) {
			defer group.Done()
			body := fmt.Sprintf(`{"name":"peer-%d","public_key":%q,"address":["10.0.0.2/32"]}`, i, key)
			results <- h.do("POST", "/api/keys", body).Code
		}(i, key)
	}
	group.Wait()
	close(results)
	success, conflict := 0, 0
	for status := range results {
		switch status {
		case http.StatusOK:
			success++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected create status %d", status)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("same-address creates: success=%d conflict=%d", success, conflict)
	}
}

func TestKeyUpdateCanClearOptionalFields(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.savePeer(t)
	e.DNS = []string{"1.1.1.1"}
	e.ServerEndpoint = "vpn.example.com:51820"
	e.ServerPubKey = testPubKeys[4]
	e.AllowedIPs = []string{"0.0.0.0/0"}
	if err := h.st.SaveVault([]*store.VaultEntry{e}); err != nil {
		t.Fatal(err)
	}
	body := `{"address":[],"dns":[],"server_endpoint":"","server_pub_key":"","allowed_ips":[]}`
	if w := h.do("PUT", "/api/keys/phone", body); w.Code != http.StatusOK {
		t.Fatalf("clear fields: %d %s", w.Code, w.Body.String())
	}
	entries, err := h.st.LoadVault()
	if err != nil || len(entries) != 1 {
		t.Fatalf("load updated entry: %v", err)
	}
	e = entries[0]
	if len(e.Address) != 0 || len(e.DNS) != 0 || len(e.AllowedIPs) != 0 || e.ServerEndpoint != "" || e.ServerPubKey != "" {
		t.Fatalf("optional fields were not cleared: %+v", e)
	}
}

func TestDefaultsSaveFailureDoesNotChangeLiveConfig(t *testing.T) {
	h := newSecurityHarness(t)
	h.s.cfg.Defaults.ServerEndpoint = "old.example.com"
	h.s.cfg.WG.AutoUp = true
	if err := os.Mkdir(filepath.Join(h.st.Dir(), "app.yaml"), 0700); err != nil {
		t.Fatal(err)
	}
	w := h.do("POST", "/api/settings/defaults", `{"server_endpoint":"new.example.com","auto_up":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure, got %d", w.Code)
	}
	if h.s.cfg.Defaults.ServerEndpoint != "old.example.com" || !h.s.cfg.WG.AutoUp {
		t.Fatal("failed persistence changed in-memory configuration")
	}
	w = h.do("POST", "/api/conf/auto-up", `{"file":"wg0.conf","enabled":false}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected auto-up persistence failure, got %d", w.Code)
	}
	if len(h.s.cfg.WG.AutoUpSkip) != 0 {
		t.Fatal("failed auto-up persistence changed in-memory configuration")
	}
}

func TestDeployRollsBackConfigWhenVaultSaveFails(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	h.savePeer(t)
	original, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.st.Dir(), 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(h.st.Dir(), 0o700)

	w := h.do("POST", "/api/keys/phone/deploy", `{}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected vault save failure, got %d: %s", w.Code, w.Body.String())
	}
	restored, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatal("config was not restored after vault save failure")
	}
}

func TestKeyGenerateRejectsMalformedBodyAndAcceptsEmptyBody(t *testing.T) {
	h := newSecurityHarness(t)
	if w := h.do("POST", "/api/keys/generate", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed generate body: got %d %s", w.Code, w.Body.String())
	}
	if w := h.do("POST", "/api/keys/generate", ""); w.Code != http.StatusOK {
		t.Fatalf("empty generate body: got %d %s", w.Code, w.Body.String())
	}
}

func TestConfDeleteRetainsFilesOnStateOrStopFailure(t *testing.T) {
	for _, failure := range []string{"query", "parse", "down"} {
		t.Run(failure, func(t *testing.T) {
			h := newSecurityHarness(t)
			h.writeConf(t, securityConf())
			if err := os.WriteFile(h.path+".bak", []byte("backup"), 0600); err != nil {
				t.Fatal(err)
			}
			h.r.dump = securityDump(false)
			switch failure {
			case "query":
				h.r.queryErr = errors.New("query failed")
			case "parse":
				h.r.dump = "invalid dump"
			case "down":
				h.r.downErr = errors.New("down failed")
			}
			w := h.do("DELETE", "/api/conf/delete?file=wg0.conf", "")
			if w.Code != 500 {
				t.Fatalf("failure ignored: %d", w.Code)
			}
			for _, path := range []string{h.path, h.path + ".bak"} {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("config or backup deleted")
				}
			}
		})
	}
}

func TestConfDeleteRejectsGlobNamesAndKeepsOtherBackups(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	for _, name := range []string{"wg0.conf.bak", "wg0.conf.bak.1", "wg1.conf.bak"} {
		if err := os.WriteFile(filepath.Join(h.s.cfg.WG.ConfDir, name), []byte("backup"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if w := h.do("DELETE", "/api/conf/delete?file=wg%2A.conf", ""); w.Code != 400 {
		t.Fatal("glob name accepted")
	}
	if w := h.do("DELETE", "/api/conf/delete?file=wg0.conf", ""); w.Code != 200 {
		t.Fatalf("delete failed: %s", w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(h.s.cfg.WG.ConfDir, "wg1.conf.bak")); err != nil {
		t.Fatal("other interface's backup removed")
	}
	if _, err := os.Stat(h.path + ".bak.1"); !os.IsNotExist(err) {
		t.Fatal("own backup not removed")
	}
}

func TestConfRevisionRejectsStaleEditorAfterPeerDeployment(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	h.savePeer(t)
	w := h.do("GET", "/api/conf/read?file=wg0.conf", "")
	var read confReadResp
	if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if w := h.do("POST", "/api/keys/phone/deploy", `{}`); w.Code != 200 {
		t.Fatal("deploy failed")
	}
	body, _ := json.Marshal(confWriteReq{File: "wg0.conf", Content: securityConf(), Revision: &read.Revision})
	w = h.do("PUT", "/api/conf/write", string(body))
	if w.Code != 409 {
		t.Fatalf("stale editor overwrote deployment: %d", w.Code)
	}
	raw, _ := os.ReadFile(h.path)
	if !strings.Contains(string(raw), testPubKeys[1]) {
		t.Fatal("peer lost")
	}
}

func TestConcurrentConfigCreationDoesNotOverwrite(t *testing.T) {
	h := newSecurityHarness(t)
	body, _ := json.Marshal(confWriteReq{File: "wg0.conf", Content: securityConf(), Create: true})
	results := make(chan int, 12)
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- h.do("PUT", "/api/conf/write", string(body)).Code }()
	}
	group.Wait()
	close(results)
	success := 0
	for status := range results {
		if status == 200 {
			success++
		} else if status != 409 {
			t.Fatalf("unexpected status: %d", status)
		}
	}
	if success != 1 {
		t.Fatalf("expected one creator, got %d", success)
	}
}

func TestConcurrentEditorAndPeerDeploymentPreservePeer(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	h.savePeer(t)
	revision := configRevision([]byte(securityConf()))
	body, _ := json.Marshal(confWriteReq{File: "wg0.conf", Content: securityConf(), Revision: &revision})
	var editor, deploy *httptest.ResponseRecorder
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); editor = h.do("PUT", "/api/conf/write", string(body)) }()
	go func() { defer group.Done(); deploy = h.do("POST", "/api/keys/phone/deploy", `{}`) }()
	group.Wait()
	if (editor.Code != 200 && editor.Code != 409) || deploy.Code != 200 || !strings.Contains(deploy.Body.String(), `"written":true`) {
		t.Fatal("concurrent write failed unexpectedly")
	}
	raw, err := os.ReadFile(h.path)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := config.Parse(string(raw))
	if err != nil || len(conf.Peers) != 1 || conf.Peers[0].PublicKey != testPubKeys[1] {
		t.Fatal("concurrent editor lost peer deployment")
	}
}

func TestKeyDeleteFailureRetainsVault(t *testing.T) {
	for _, failure := range []string{"parse", "sync"} {
		t.Run(failure, func(t *testing.T) {
			h := newSecurityHarness(t)
			e := h.savePeer(t)
			h.r.dump = securityDump(true)
			if failure == "parse" {
				h.writeConf(t, "broken")
			} else {
				h.writeConf(t, securityConf()+fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", e.PublicKey))
				h.r.syncErr = errors.New("sync failed")
			}
			w := h.do("DELETE", "/api/keys/phone", "")
			if w.Code != 409 {
				t.Fatalf("failure not reported: %d", w.Code)
			}
			entries, err := h.st.LoadVault()
			if err != nil || len(entries) != 1 || entries[0].PublicKey != e.PublicKey {
				t.Fatal("vault entry lost")
			}
			if failure == "sync" && !entries[0].PendingApply {
				t.Fatal("pending retry not persisted")
			}
		})
	}
}

func TestDeletingPeerOnStoppedInterfaceSucceeds(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.savePeer(t)
	h.writeConf(t, securityConf()+fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", e.PublicKey))
	h.r.syncErr = errors.New("interface does not exist")
	w := h.do("DELETE", "/api/keys/phone", "")
	if w.Code != 200 || h.r.syncCalls != 0 {
		t.Fatalf("absent interface caused removal failure: %d", w.Code)
	}
	entries, err := h.st.LoadVault()
	if err != nil || len(entries) != 0 {
		t.Fatal("stopped interface prevented vault deletion")
	}
	raw, _ := os.ReadFile(h.path)
	if strings.Contains(string(raw), e.PublicKey) {
		t.Fatal("persistent peer not removed")
	}
}

func TestConcurrentSetupDoesNotReplaceFirstAccount(t *testing.T) {
	h := newSecurityHarness(t)
	var group sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, 2)
	for i := range responses {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			responses[i] = h.do("POST", "/api/setup", fmt.Sprintf(`{"username":"admin%d","password":"password%d"}`, i, i))
		}(i)
	}
	group.Wait()
	winner := -1
	for i, response := range responses {
		if response.Code == 200 {
			if winner != -1 {
				t.Fatal("multiple accounts created")
			}
			winner = i
		} else if response.Code != 401 {
			t.Fatalf("unexpected setup status: %d", response.Code)
		}
	}
	u, err := h.st.GetUser()
	if winner < 0 || err != nil || u.Username != fmt.Sprintf("admin%d", winner) {
		t.Fatal("first account was overwritten")
	}
}

func TestUnloadFailureCanBeRetriedAfterListRefresh(t *testing.T) {
	h := newSecurityHarness(t)
	e := h.savePeer(t)
	h.writeConf(t, securityConf()+fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\n", e.PublicKey))
	h.r.dump = securityDump(true)
	h.r.syncErr = errors.New("sync failed")
	if w := h.do("POST", "/api/keys/phone/unload", `{}`); w.Code != 200 {
		t.Fatal("unload failed")
	}
	w := h.do("GET", "/api/keys", "")
	var list struct {
		Entries []keyView `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Loaded || !list.Entries[0].PendingApply || !list.Entries[0].NeedsApply {
		t.Fatal("refresh lost pending unload state")
	}
	before, _ := os.ReadFile(h.path)
	h.r.syncErr = nil
	h.r.onSync = func() { h.r.dump = securityDump(false) }
	w = h.do("POST", "/api/keys/phone/apply", `{}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"applied":true`) {
		t.Fatal("retry not applied")
	}
	after, _ := os.ReadFile(h.path)
	if string(before) != string(after) || strings.Contains(string(after), e.PublicKey) {
		t.Fatal("retry reloaded removed peer")
	}
	entries, _ := h.st.LoadVault()
	if entries[0].PendingApply {
		t.Fatal("pending state not cleared")
	}
}

func TestChangingInterfaceRequiresUnloadedPeer(t *testing.T) {
	for _, state := range []string{"config", "runtime", "pending"} {
		t.Run(state, func(t *testing.T) {
			h := newSecurityHarness(t)
			e := h.savePeer(t)
			h.writeConf(t, securityConf())
			switch state {
			case "config":
				h.writeConf(t, securityConf()+fmt.Sprintf("\n[Peer]\nPublicKey = %s\n", e.PublicKey))
			case "runtime":
				h.r.dump = securityDump(true)
			case "pending":
				e.PendingApply = true
				if err := h.st.SaveVault([]*store.VaultEntry{e}); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(h.s.cfg.WG.ConfDir, "wg1.conf"), []byte(securityConf()), 0600); err != nil {
				t.Fatal(err)
			}
			if w := h.do("PUT", "/api/keys/phone", `{"iface":"wg1"}`); w.Code != 409 {
				t.Fatalf("loaded peer moved: %d", w.Code)
			}
			w := h.do("POST", "/api/keys/phone/deploy", `{"iface":"wg1"}`)
			if !strings.Contains(w.Body.String(), `"error"`) {
				t.Fatal("explicit deployment bypassed move protection")
			}
			entries, _ := h.st.LoadVault()
			if entries[0].Iface != "wg0" {
				t.Fatal("old interface lost")
			}
		})
	}
}

func TestExplicitDeploymentPersistsTargetInterface(t *testing.T) {
	h := newSecurityHarness(t)
	h.savePeer(t)
	if err := os.WriteFile(filepath.Join(h.s.cfg.WG.ConfDir, "wg1.conf"), []byte(securityConf()), 0600); err != nil {
		t.Fatal(err)
	}
	w := h.do("POST", "/api/keys/phone/deploy", `{"iface":"wg1"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"written":true`) {
		t.Fatal("deployment failed")
	}
	entries, _ := h.st.LoadVault()
	if entries[0].Iface != "wg1" {
		t.Fatal("deployment target not persisted")
	}
}

func TestSetupCanResumeWithoutReplacingCredentials(t *testing.T) {
	h := newSecurityHarness(t)
	u := h.saveUser(t, false)
	w := h.do("GET", "/api/setup/status", "")
	if !strings.Contains(w.Body.String(), `"needs_setup":true`) {
		t.Fatal("unfinished enrollment hidden")
	}
	if w := h.do("POST", "/api/setup", `{"username":"tester","password":"wrong-password"}`); w.Code != 401 {
		t.Fatal("secret disclosed without credential verification")
	}
	w = h.do("POST", "/api/setup", `{"username":"tester","password":"old-password"}`)
	var resp struct {
		Secret string `json:"secret"`
		QR     string `json:"qr_data_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || resp.Secret != u.TOTPSecret || !strings.HasPrefix(resp.QR, "data:image/png;base64,") {
		t.Fatal("enrollment not resumed")
	}
	code, err := totp.GenerateCode(u.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w = h.do("POST", "/api/setup/verify", fmt.Sprintf(`{"code":%q}`, code))
	if w.Code != 200 {
		t.Fatalf("resume verification failed: %d", w.Code)
	}
	saved, _ := h.st.GetUser()
	if !saved.TOTPEnabled || saved.PasswordHash != u.PasswordHash {
		t.Fatal("credentials changed during resume")
	}
}

func TestPasswordChangeRevokesOtherSessionsAndTickets(t *testing.T) {
	h := newSecurityHarness(t)
	u := h.saveUser(t, true)
	other, _ := h.s.sess.NewSession(u.Username)
	ticket, _ := h.s.sess.NewTicket(u.Username)
	w := h.do("POST", "/api/settings/password", `{"current_password":"old-password","new_password":"new-password"}`)
	if w.Code != 200 {
		t.Fatalf("password change failed: %d", w.Code)
	}
	if _, ok := h.s.sess.Get(other.Token); ok {
		t.Fatal("other session survived")
	}
	if _, ok := h.s.sess.Get(h.session.Token); !ok {
		t.Fatal("verified caller unexpectedly revoked")
	}
	code, _ := totp.GenerateCode(u.TOTPSecret, time.Now())
	w = h.do("POST", "/api/auth/totp", fmt.Sprintf(`{"ticket":%q,"code":%q}`, ticket, code))
	if w.Code != 401 {
		t.Fatal("old login ticket survived password change")
	}
}

func TestLoginCannotResetAccountTOTPFailureLimit(t *testing.T) {
	h := newSecurityHarness(t)
	h.saveUser(t, true)
	for i := 0; i < 5; i++ {
		w := h.do("POST", "/api/auth/login", `{"username":"tester","password":"old-password"}`)
		var login loginResp
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &login) != nil {
			t.Fatal("ticket request failed before lockout")
		}
		w = h.do("POST", "/api/auth/totp", fmt.Sprintf(`{"ticket":%q,"code":"invalid"}`, login.Ticket))
		if w.Code != 401 {
			t.Fatalf("invalid code accepted: %d", w.Code)
		}
	}
	w := h.do("POST", "/api/auth/login", `{"username":"tester","password":"old-password"}`)
	if w.Code != 429 {
		t.Fatalf("correct password bypassed TOTP lockout: %d", w.Code)
	}
}

func TestTOTPResetStagesSecretWithoutDisablingOldAuthenticator(t *testing.T) {
	h := newSecurityHarness(t)
	u := h.saveUser(t, true)
	other, _ := h.s.sess.NewSession(u.Username)
	ticket, _ := h.s.sess.NewTicket(u.Username)
	w := h.do("POST", "/api/settings/totp/reset", `{"password":"old-password"}`)
	if w.Code != 200 {
		t.Fatalf("reset failed: %d", w.Code)
	}
	saved, _ := h.st.GetUser()
	if !saved.TOTPEnabled || saved.TOTPSecret != u.TOTPSecret || saved.PendingTOTPSecret == "" {
		t.Fatal("active 2FA was replaced before verification")
	}
	if _, ok := h.s.sess.Get(other.Token); ok {
		t.Fatal("other session survived reset")
	}
	if _, err := h.s.sess.ConsumeTicket(ticket, "invalid", u.TOTPSecret); err == nil {
		t.Fatal("old ticket survived")
	}
	// Restarting the server must still permit login with the verified old secret.
	h.s = New(h.s.cfg, h.st, h.r, true)
	w = h.do("POST", "/api/auth/login", `{"username":"tester","password":"old-password"}`)
	var login loginResp
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 {
		t.Fatal("interrupted reset locked the account")
	}
	oldCode, _ := totp.GenerateCode(u.TOTPSecret, time.Now())
	w = h.do("POST", "/api/auth/totp", fmt.Sprintf(`{"ticket":%q,"code":%q}`, login.Ticket, oldCode))
	if w.Code != 200 {
		t.Fatal("old authenticator stopped working")
	}
	var loggedIn struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &loggedIn); err != nil {
		t.Fatal(err)
	}
	h.session = &auth.Session{Token: w.Result().Cookies()[0].Value, CSRF: loggedIn.CSRF}
	newCode, _ := totp.GenerateCode(saved.PendingTOTPSecret, time.Now())
	w = h.do("POST", "/api/settings/totp/verify", fmt.Sprintf(`{"code":%q}`, newCode))
	if w.Code != 200 {
		t.Fatal("staged verification failed")
	}
	committed, _ := h.st.GetUser()
	if committed.TOTPSecret != saved.PendingTOTPSecret || committed.PendingTOTPSecret != "" || !committed.TOTPEnabled {
		t.Fatal("new secret not committed")
	}
}

func TestSaveConfigWriteIsRejectedWithoutChangingFile(t *testing.T) {
	h := newSecurityHarness(t)
	h.writeConf(t, securityConf())
	body, _ := json.Marshal(confWriteReq{File: "wg0.conf", Content: securityConf() + "SaveConfig = true\n"})
	w := h.do("PUT", "/api/conf/write", string(body))
	if w.Code != 400 {
		t.Fatal("unsafe SaveConfig accepted")
	}
	raw, _ := os.ReadFile(h.path)
	if string(raw) != securityConf() {
		t.Fatal("unsafe config written")
	}
}
