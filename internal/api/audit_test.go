package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRotateAuditLogKeepsThreeBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	files := map[string]string{
		path:        "current",
		path + ".1": "one",
		path + ".2": "two",
		path + ".3": "three",
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := rotateAuditLog(path); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		path + ".1": "current",
		path + ".2": "one",
		path + ".3": "two",
	} {
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("active audit log still exists after rotation")
	}
}

func TestAppendAuditRotatesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendAudit(path, []byte("new\n"), 3); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(active) != "new\n" {
		t.Errorf("active audit log = %q, want %q", active, "new\n")
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "old" {
		t.Errorf("audit.log.1 = %q, want %q", backup, "old")
	}
}

func TestClientIPUsesForwardedAddressOnlyFromLoopbackProxy(t *testing.T) {
	proxied := httptest.NewRequest("GET", "/", nil)
	proxied.RemoteAddr = "127.0.0.1:8080"
	proxied.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.8")
	if got := clientIP(proxied); got != "203.0.113.8" {
		t.Fatalf("proxy client IP = %q", got)
	}
	proxied.Header.Set("X-Real-IP", "192.0.2.24")
	if got := clientIP(proxied); got != "192.0.2.24" {
		t.Fatalf("real IP header not used: %q", got)
	}

	direct := httptest.NewRequest("GET", "/", nil)
	direct.RemoteAddr = "198.51.100.2:3456"
	direct.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIP(direct); got != "198.51.100.2" {
		t.Fatalf("untrusted forwarded address accepted: %q", got)
	}
}

func TestSecureRequestTrustsTLSAndLoopbackProxyOnly(t *testing.T) {
	if !secureRequest(httptest.NewRequest("GET", "https://example.test/", nil)) {
		t.Fatal("direct TLS request was not secure")
	}

	proxied := httptest.NewRequest("GET", "/", nil)
	proxied.RemoteAddr = "127.0.0.1:8080"
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if !secureRequest(proxied) {
		t.Fatal("HTTPS from loopback proxy was not secure")
	}

	direct := httptest.NewRequest("GET", "/", nil)
	direct.RemoteAddr = "198.51.100.2:3456"
	direct.Header.Set("X-Forwarded-Proto", "https")
	if secureRequest(direct) {
		t.Fatal("untrusted forwarded protocol accepted")
	}
}
