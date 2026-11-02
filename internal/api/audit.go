package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yq/wireguard-manager/internal/auth"
)

const (
	auditMaxBytes    int64 = 10 << 20 // 10 MiB per file
	auditBackupCount       = 3
)

// Audit appends a structured event to <data-dir>/audit.log (JSONL).
func (s *Server) Audit(r *http.Request, action string, detail string) {
	entry := map[string]any{
		"time":   time.Now().UTC().Format(time.RFC3339),
		"ip":     clientIP(r),
		"action": action,
		"detail": detail,
	}
	if sess, ok := s.sess.Get(auth.CookieToken(r)); ok {
		entry["user"] = sess.Username
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	b = append(b, '\n')

	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if err := appendAudit(filepath.Join(s.store.Dir(), "audit.log"), b, auditMaxBytes); err != nil {
		log.Printf("[wgm] audit write failed: %v", err)
	}
}

func appendAudit(path string, line []byte, maxBytes int64) error {
	var rotationErr error
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(line)) > maxBytes {
		// A rotation failure must not prevent the current event from being recorded.
		rotationErr = rotateAuditLog(path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return rotationErr
}

func rotateAuditLog(path string) error {
	oldest := fmt.Sprintf("%s.%d", path, auditBackupCount)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := auditBackupCount; i >= 1; i-- {
		src := path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", path, i)

		if _, err := os.Stat(src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if remote := net.ParseIP(host); remote != nil && remote.IsLoopback() {
		if ip := parseForwardedIP(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if ip := parseForwardedIP(forwarded[len(forwarded)-1]); ip != "" {
			return ip
		}
	}
	return host
}

func parseForwardedIP(value string) string {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	}
	return false
}
