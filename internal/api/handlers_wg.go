package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/yq/wireguard-manager/internal/wg"
)

func nowUTC() time.Time { return time.Now().UTC().Truncate(time.Second) }

// --- status (wg show all dump) -----------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.wg.ShowAllDump()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ifaces, err := wg.ParseDump(out)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, ic := range ifaces {
		ic.PrivateKey = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"demo":       s.demo,
		"interfaces": ifaces,
	})
}

// --- wg-quick up / down ---------------------------------------------------------

func (s *Server) handleQuick(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface  string `json:"iface"`
		Action string `json:"action"` // "up" | "down"
	}
	if !readJSON(w, r, &req) {
		return
	}
	iface := sanitizeIface(req.Iface)
	if iface == "" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	var err error
	switch req.Action {
	case "up":
		err = s.wg.QuickUp(iface)
	case "down":
		err = s.wg.QuickDown(iface)
	case "restart":
		_ = s.wg.QuickDown(iface)
		err = s.wg.QuickUp(iface)
	default:
		writeErr(w, http.StatusBadRequest, "action must be up, down or restart")
		return
	}
	if err != nil {
		s.Audit(r, "wg.quick."+req.Action, req.Iface+" failed")
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit(r, "wg.quick."+req.Action, req.Iface)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- direct `wg set` operations --------------------------------------------------------

type setPeerReq struct {
	Iface     string `json:"iface"`
	PublicKey string `json:"public_key"`
	Remove    bool   `json:"remove"`
}

// handleSetPeer only supports removing a peer from a running interface.
// Runtime edits (endpoint/allowed_ips/keepalive) are intentionally not
// offered; manage them via the key vault and deploy/syncconf instead.
func (s *Server) handleSetPeer(w http.ResponseWriter, r *http.Request) {
	var req setPeerReq
	if !readJSON(w, r, &req) {
		return
	}
	iface := sanitizeIface(req.Iface)
	if iface == "" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	if !req.Remove {
		writeErr(w, http.StatusBadRequest, "only peer removal is supported")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != 32 {
		writeErr(w, http.StatusBadRequest, "invalid public key")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	if err := s.wg.SetPeerRemove(iface, req.PublicKey); err != nil {
		s.Audit(r, "wg.set.peer.remove", req.Iface+" failed: "+err.Error())
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit(r, "wg.set.peer.remove", req.Iface+" "+req.PublicKey[:12]+"…")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
