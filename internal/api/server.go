// Package api wires HTTP routing, authentication and all JSON handlers.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/yq/wireguard-manager/internal/auth"
	"github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

// Server holds every dependency needed by the handlers.
type Server struct {
	cfg     *config.AppConfig
	store   *store.Store
	sess    *auth.Manager
	limiter *auth.Limiter
	wg      wg.Backend
	demo    bool

	vaultMu sync.Mutex   // serializes read-modify-write cycles on vault.yaml
	cfgMu   sync.RWMutex // serializes app.yaml reads and read-modify-write cycles
	auditMu sync.Mutex   // serializes audit.log writes and rotations
	confMu  sync.Mutex   // serializes config files and WG mutations; acquire after vaultMu
	userMu  sync.Mutex   // serializes credentials, enrollment and session issuance
}

// New builds a Server.
func New(cfg *config.AppConfig, st *store.Store, backend wg.Backend, demo bool) *Server {
	return &Server{
		cfg:     cfg,
		store:   st,
		sess:    auth.NewManager(),
		limiter: auth.NewLimiter(),
		wg:      backend,
		demo:    demo,
	}
}

// RunConfigOperation lets startup WG operations share the same lock as HTTP
// file edits and interface mutations. The callback must not acquire vaultMu.
func (s *Server) RunConfigOperation(operation func()) {
	s.confMu.Lock()
	defer s.confMu.Unlock()
	operation()
}

// configSnapshot returns a copy that can safely be used after releasing cfgMu.
// The slice is cloned because AppConfig is otherwise only a shallow copy.
func (s *Server) configSnapshot() config.AppConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return cloneAppConfig(s.cfg)
}

func (s *Server) confDir() string {
	return s.configSnapshot().WG.ConfDir
}

func cloneAppConfig(cfg *config.AppConfig) config.AppConfig {
	clone := *cfg
	clone.WG = cfg.WG
	clone.WG.AutoUpSkip = append([]string(nil), cfg.WG.AutoUpSkip...)
	return clone
}

// Router assembles the full application handler.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	// --- public ---------------------------------------------------------
	mux.HandleFunc("GET /api/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/setup/verify", s.handleSetupVerify)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/totp", s.handleTOTP)
	mux.HandleFunc("POST /api/auth/logout", s.auth(s.handleLogout))

	// --- session-scoped ---------------------------------------------------
	mux.HandleFunc("GET /api/me", s.auth(s.handleMe))
	mux.HandleFunc("POST /api/settings/password", s.auth(s.handlePassword))
	mux.HandleFunc("POST /api/settings/totp/reset", s.auth(s.handleTOTPReset))
	mux.HandleFunc("POST /api/settings/totp/verify", s.auth(s.handleTOTPVerify))
	mux.HandleFunc("GET /api/settings/defaults", s.auth(s.handleDefaultsGet))
	mux.HandleFunc("POST /api/settings/defaults", s.auth(s.handleDefaultsSet))

	// --- wireguard --------------------------------------------------------
	mux.HandleFunc("GET /api/status", s.auth(s.handleStatus))
	mux.HandleFunc("POST /api/wg/quick", s.auth(s.handleQuick))
	mux.HandleFunc("POST /api/wg/set/peer", s.auth(s.handleSetPeer))

	// --- config files -------------------------------------------------------
	mux.HandleFunc("GET /api/conf/files", s.auth(s.handleConfFiles))
	mux.HandleFunc("GET /api/conf/read", s.auth(s.handleConfRead))
	mux.HandleFunc("PUT /api/conf/write", s.auth(s.handleConfWrite))
	mux.HandleFunc("DELETE /api/conf/delete", s.auth(s.handleConfDelete))
	mux.HandleFunc("GET /api/conf/auto-up", s.auth(s.handleConfAutoUpGet))
	mux.HandleFunc("POST /api/conf/auto-up", s.auth(s.handleConfAutoUpSet))

	// --- key vault ----------------------------------------------------------
	mux.HandleFunc("GET /api/keys", s.auth(s.handleKeysList))
	mux.HandleFunc("POST /api/keys/generate", s.auth(s.handleKeysGenerate))
	mux.HandleFunc("GET /api/keys/next-address", s.auth(s.handleNextAddress))
	mux.HandleFunc("POST /api/keys", s.auth(s.handleKeyCreate))
	mux.HandleFunc("PUT /api/keys/{id}", s.auth(s.handleKeyUpdate))
	mux.HandleFunc("DELETE /api/keys/{id}", s.auth(s.handleKeyDelete))
	mux.HandleFunc("POST /api/keys/{id}/deploy", s.auth(s.handleKeyDeploy))
	mux.HandleFunc("POST /api/keys/{id}/unload", s.auth(s.handleKeyUnload))
	mux.HandleFunc("POST /api/keys/{id}/apply", s.auth(s.handleKeyApply))
	mux.HandleFunc("GET /api/keys/{id}/client-config", s.auth(s.handleClientConfig))
	mux.HandleFunc("GET /api/keys/{id}/qrcode", s.auth(s.handleClientQR))

	return s.withRecovery(mux)
}

// withRecovery turns panics into 500s and logs requests.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Printf("[wgm] panic %s %s: %v\n", r.Method, r.URL.Path, rec)
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// auth guards handlers requiring an authenticated admin session and
// enforces the CSRF token on state-changing methods.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := auth.CookieToken(r)
		sess, ok := s.sess.Get(tok)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		if !safeMethod(r.Method) && r.Header.Get("X-CSRF-Token") != sess.CSRF {
			writeErr(w, http.StatusForbidden, "missing CSRF token")
			return
		}
		next(w, r)
	}
}

func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// --- JSON helpers ------------------------------------------------------------

type errBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errBody{Error: msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSON(w, r, v, false)
}

// readOptionalJSON accepts an empty body but rejects malformed or trailing JSON.
func readOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSON(w, r, v, true)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return true
		}
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// sanitizeFileName rejects path traversal in user-supplied file names.
func sanitizeFileName(name string) error {
	if !strings.HasSuffix(name, ".conf") || !config.ValidIfaceName(strings.TrimSuffix(name, ".conf")) {
		return fmt.Errorf("invalid file name")
	}
	return nil
}
