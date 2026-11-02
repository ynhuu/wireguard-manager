package api

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
)

// GET /api/settings/defaults returns peer-creation defaults and startup options.
func (s *Server) handleDefaultsGet(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	endpoint := s.cfg.Defaults.ServerEndpoint
	autoUp := s.cfg.WG.AutoUp
	defaultIface := s.cfg.WG.DefaultIface
	writeJSON(w, http.StatusOK, map[string]any{
		"server_endpoint": endpoint,
		"auto_up":         autoUp,
		"default_iface":   defaultIface,
	})
}

// POST /api/settings/defaults persists changes into app.yaml.
// auto_up is optional (*bool): omitted means unchanged.
func (s *Server) handleDefaultsSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerEndpoint string `json:"server_endpoint"`
		AutoUp         *bool  `json:"auto_up,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	endpoint := strings.TrimSpace(req.ServerEndpoint)
	if err := validateEndpointHost(endpoint); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	next := cloneAppConfig(s.cfg)
	next.Defaults.ServerEndpoint = endpoint
	detail := "server_endpoint=" + endpoint
	if req.AutoUp != nil {
		next.WG.AutoUp = *req.AutoUp
		detail += fmt.Sprintf(", auto_up=%v", *req.AutoUp)
	}
	path := filepath.Join(s.store.Dir(), "app.yaml")
	if err := next.Save(path); err != nil {
		writeErr(w, http.StatusInternalServerError, "save app.yaml: "+err.Error())
		return
	}
	*s.cfg = next
	s.Audit(r, "settings.defaults", detail)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func validateEndpointHost(host string) error {
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("server endpoint 只填写公网域名或 IP，不要填写端口")
	}
	if len(host) > 253 || strings.ContainsAny(host, " /?#") {
		return fmt.Errorf("invalid server endpoint host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid server endpoint host")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("invalid server endpoint host")
			}
		}
	}
	return nil
}
