package api

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/skip2/go-qrcode"

	"github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/wg"
)

// keyView is the API representation of a vault entry (secrets omitted).
type keyView struct {
	store.VaultEntry
	HasPrivateKey   bool   `json:"has_private_key"`
	HasPresharedKey bool   `json:"has_preshared_key"`
	Loaded          bool   `json:"loaded"`
	ConfigError     string `json:"config_error,omitempty"`
	RuntimeLoaded   *bool  `json:"runtime_loaded,omitempty"`
	NeedsApply      bool   `json:"needs_apply"`
	RuntimeError    string `json:"runtime_error,omitempty"`
}

// --- listing / CRUD -----------------------------------------------------------

// lockVault acquires the vault mutex and returns the current entries.
// Callers MUST schedule the unlock themselves (defer s.vaultMu.Unlock()
// immediately after a successful call is the recommended pattern).
func (s *Server) lockVault(w http.ResponseWriter) ([]*store.VaultEntry, bool) {
	s.vaultMu.Lock()
	keepLock := false
	defer func() {
		if !keepLock {
			s.vaultMu.Unlock()
		}
	}()
	entries, err := s.store.LoadVault()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	keepLock = true
	return entries, true
}

func (s *Server) handleKeysList(w http.ResponseWriter, r *http.Request) {
	cfg := s.configSnapshot()
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	s.confMu.Lock()
	defer s.confMu.Unlock()
	items := make([]keyView, len(entries))
	for i, entry := range entries {
		items[i] = keyView{
			VaultEntry:      *entry,
			HasPrivateKey:   entry.PrivateKeyEnc != "",
			HasPresharedKey: entry.PresharedKeyEnc != "",
		}
		items[i].PrivateKeyEnc = ""
		items[i].PresharedKeyEnc = ""
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"entries": items})
		return
	}
	running, runtimeErr := s.runtimePeers()
	type configState struct {
		peers map[string]bool
		err   error
	}
	// Parse each interface once per request, rather than once per vault entry.
	configs := make(map[string]configState)
	for i := range items {
		item := &items[i]
		iface := firstNonEmpty(sanitizeIface(item.Iface), cfg.WG.DefaultIface)
		peers, ifaceRunning := running[iface]
		if runtimeErr != nil {
			item.RuntimeError = runtimeErr.Error()
		} else {
			loaded := peers[item.PublicKey]
			item.RuntimeLoaded = &loaded
		}
		state, cached := configs[iface]
		if !cached {
			raw, err := os.ReadFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"))
			if err == nil {
				var conf *config.Config
				conf, err = config.Parse(string(raw))
				if err == nil {
					state.peers = make(map[string]bool, len(conf.Peers))
					for _, peer := range conf.Peers {
						state.peers[peer.PublicKey] = true
					}
				}
			}
			if !os.IsNotExist(err) {
				state.err = err
			}
			configs[iface] = state
		}
		if state.err != nil {
			item.ConfigError = state.err.Error()
			continue
		}
		item.Loaded = state.peers[item.PublicKey]
		item.NeedsApply = ifaceRunning && item.RuntimeLoaded != nil && item.Loaded != *item.RuntimeLoaded
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": items})
}

func (s *Server) findEntry(entries []*store.VaultEntry, id string) (*store.VaultEntry, int) {
	for i, e := range entries {
		if e.ID == id {
			return e, i
		}
	}
	return nil, -1
}

// handleKeysGenerate mints a fresh keypair; PSK only when explicitly requested.
func (s *Server) handleKeysGenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WithPresharedKey bool `json:"with_preshared_key"`
	}
	if !readOptionalJSON(w, r, &req) {
		return
	}

	priv, err := wg.GeneratePrivateKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]string{
		"private_key": priv,
		"public_key":  wg.PublicKeyFromPrivate(priv),
	}
	if req.WithPresharedKey {
		psk, err := wg.GeneratePresharedKey()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp["preshared_key"] = psk
	}
	writeJSON(w, http.StatusOK, resp)
}

type deployOpt struct {
	Iface        string `json:"iface,omitempty"`         // default: cfg default_iface
	ApplyRuntime bool   `json:"apply_runtime,omitempty"` // wg syncconf after write
}

type keyCreateReq struct {
	Name           string     `json:"name"`
	Iface          string     `json:"iface,omitempty"`
	PublicKey      string     `json:"public_key"`
	PrivateKey     string     `json:"private_key,omitempty"`
	PresharedKey   string     `json:"preshared_key,omitempty"`
	Address        []string   `json:"address,omitempty"`
	DNS            []string   `json:"dns,omitempty"`
	ServerEndpoint string     `json:"server_endpoint,omitempty"`
	ServerPubKey   string     `json:"server_pub_key,omitempty"`
	AllowedIPs     []string   `json:"allowed_ips,omitempty"`
	Keepalive      int        `json:"keepalive,omitempty"`
	Notes          string     `json:"notes,omitempty"`
	DeployToConfig *deployOpt `json:"deploy_to_config,omitempty"`
}

func (s *Server) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req keyCreateReq
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || req.PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "name and public_key are required")
		return
	}
	if req.DeployToConfig != nil && req.DeployToConfig.Iface != "" {
		req.Iface = req.DeployToConfig.Iface
	}
	if req.Iface != "" && sanitizeIface(req.Iface) == "" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	// 密钥格式校验（base64 / 32 字节），避免坏数据流入客户端配置
	if err := config.ValidateKey(req.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid public_key: "+err.Error())
		return
	}
	for field, val := range map[string]string{"private_key": req.PrivateKey, "preshared_key": req.PresharedKey} {
		if val == "" {
			continue
		}
		if err := config.ValidateKey(val); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid "+field+": "+err.Error())
			return
		}
	}
	if req.PrivateKey != "" && wg.PublicKeyFromPrivate(req.PrivateKey) != req.PublicKey {
		writeErr(w, http.StatusBadRequest, "private_key does not match public_key")
		return
	}
	// Endpoint 留空时，根据目标接口的 ListenPort 补全设置页中的服务端主机。
	endpoint := strings.TrimSpace(req.ServerEndpoint)
	if endpoint == "" {
		var err error
		endpoint, err = s.defaultEndpointForIface(req.Iface)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	for _, e := range entries {
		if e.PublicKey == req.PublicKey || e.Name == req.Name {
			writeErr(w, http.StatusConflict, "entry with same name or public key exists")
			return
		}
	}
	entry := &store.VaultEntry{
		ID:             fmt.Sprintf("%d-%06d", time.Now().UnixNano(), time.Now().Nanosecond()%1000000),
		Name:           req.Name,
		Iface:          sanitizeIface(req.Iface),
		PublicKey:      req.PublicKey,
		Address:        req.Address,
		DNS:            req.DNS,
		ServerEndpoint: endpoint,
		ServerPubKey:   req.ServerPubKey,
		AllowedIPs:     req.AllowedIPs,
		Keepalive:      req.Keepalive,
		Notes:          req.Notes,
		CreatedAt:      nowUTC(),
		UpdatedAt:      nowUTC(),
	}
	if err := validateVaultEntry(entry); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	if err := s.addressConflict(entry, entries); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if req.PrivateKey != "" {
		enc, err := s.store.Encrypt([]byte(req.PrivateKey))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt private key")
			return
		}
		entry.PrivateKeyEnc = enc
	}
	if req.PresharedKey != "" {
		enc, err := s.store.Encrypt([]byte(req.PresharedKey))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt preshared key")
			return
		}
		entry.PresharedKeyEnc = enc
	}
	all := append(entries, entry)
	if err := s.store.SaveVault(all); err != nil {
		writeErr(w, http.StatusInternalServerError, "save vault")
		return
	}
	s.Audit(r, "keys.create", entry.Name)

	resp := map[string]any{"id": entry.ID}
	if req.DeployToConfig != nil {
		original := *entry
		result := s.deployEntryToConfig(entry, req.DeployToConfig)
		resp["deploy"] = result
		// deploy 会回写 entry.Iface，重新落盘
		if err := s.store.SaveVault(all); err != nil {
			resp["save_error"] = err.Error()
			if rollbackErr := s.rollbackDeployment(entry, original, result, req.DeployToConfig.ApplyRuntime); rollbackErr != nil {
				resp["rollback_error"] = rollbackErr.Error()
			}
			writeJSON(w, http.StatusInternalServerError, resp)
			return
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// deployEntryToConfig writes the peer into <conf_dir>/<iface>.conf,
// requiring an existing interface configuration. Caller holds vaultMu and confMu.
func (s *Server) deployEntryToConfig(e *store.VaultEntry, opt *deployOpt) map[string]any {
	cfg := s.configSnapshot()
	// 优先级：显式指定 > entry 记录的接口 > 默认接口
	iface := firstNonEmpty(
		sanitizeIface(opt.Iface),
		sanitizeIface(e.Iface),
		cfg.WG.DefaultIface,
	)
	result := map[string]any{"iface": iface, "file": filepath.Join(cfg.WG.ConfDir, iface+".conf")}
	if (opt.Iface != "" && sanitizeIface(opt.Iface) == "") || !config.ValidIfaceName(iface) {
		result["error"] = "invalid interface name"
		return result
	}
	if iface != firstNonEmpty(sanitizeIface(e.Iface), cfg.WG.DefaultIface) {
		if err := s.requirePeerUnloaded(e); err != nil {
			result["error"] = err.Error()
			return result
		}
	}
	if err := validateVaultEntry(e); err != nil {
		result["error"] = err.Error()
		return result
	}
	if len(e.Address) == 0 {
		result["error"] = "client Address is required"
		return result
	}
	entries, err := s.store.LoadVault()
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	target := *e
	target.Iface = iface
	if err := s.addressConflict(&target, entries); err != nil {
		result["error"] = err.Error()
		return result
	}

	peer := config.Peer{PublicKey: e.PublicKey, AllowedIPs: e.Address}
	if e.PresharedKeyEnc != "" {
		pskRaw, err := s.store.Decrypt(e.PresharedKeyEnc)
		if err != nil {
			result["error"] = "decrypt preshared key failed"
			return result
		}
		peer.PresharedKey = string(pskRaw)
	}

	path := result["file"].(string)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// 不再从运行态重建骨架：dump 里没有 Address/PostUp，生成的文件
		// wg-quick up 后无隧道 IP、NAT 失效。宁可拒绝也不产出坏配置。
		result["error"] = fmt.Sprintf(
			"%s does not exist; create the interface config via the editor first",
			filepath.Base(path),
		)
		return result
	}
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	conf, err := config.Parse(string(raw))
	if err != nil {
		result["error"] = "existing config failed to parse: " + err.Error()
		return result
	}

	conf.UpsertPeer(peer)
	out := conf.Render()

	backup, err := writeConfigFile(path, out)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	if backup != "" {
		result["backup"] = backup
	}
	result["written"] = true
	e.Iface = iface

	if opt.ApplyRuntime {
		aerr := s.wg.SyncConf(iface)
		setApplyResult(result, aerr)
		e.PendingApply = aerr != nil
	}
	return result
}

// rollbackDeployment restores the config and in-memory vault entry when the
// second half of a deploy cannot persist the updated vault metadata.
func (s *Server) rollbackDeployment(e *store.VaultEntry, original store.VaultEntry, result map[string]any, applyRuntime bool) error {
	*e = original
	if result["written"] != true {
		return nil
	}
	path, _ := result["file"].(string)
	backup, _ := result["backup"].(string)
	if path == "" || backup == "" {
		return fmt.Errorf("no backup available for config rollback")
	}
	if err := restoreConfigFile(path, backup); err != nil {
		return err
	}
	if applyRuntime && (result["applied"] == true || result["apply_error"] != nil) {
		iface, _ := result["iface"].(string)
		if err := s.wg.SyncConf(iface); err != nil {
			return fmt.Errorf("restore runtime config: %w", err)
		}
	}
	return nil
}

// handleKeyDeploy writes an existing vault entry's peer section into the
// server config file.
func (s *Server) handleKeyDeploy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var opt deployOpt
	if !readJSON(w, r, &opt) {
		return
	}
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	e, _ := s.findEntry(entries, id)
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if len(e.Address) == 0 {
		writeErr(w, http.StatusBadRequest, "entry has no client address; set Address first")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	original := *e
	result := s.deployEntryToConfig(e, &opt)
	if err := s.store.SaveVault(entries); err != nil {
		result["save_error"] = err.Error()
		if rollbackErr := s.rollbackDeployment(e, original, result, opt.ApplyRuntime); rollbackErr != nil {
			result["rollback_error"] = rollbackErr.Error()
		}
		s.Audit(r, "keys.deploy.failed", e.Name+": vault save failed")
		writeJSON(w, http.StatusInternalServerError, result)
		return
	}
	s.Audit(r, "keys.deploy", e.Name+" -> "+fmt.Sprint(result["file"]))
	writeJSON(w, http.StatusOK, result)
}

// keyUpdateReq uses pointers for optional fields: omitted keeps the value,
// while an explicit empty value clears it. Keepalive 0 turns it off.
type keyUpdateReq struct {
	keyCreateReq
	PresharedKey   *string   `json:"preshared_key,omitempty"`
	Address        *[]string `json:"address,omitempty"`
	DNS            *[]string `json:"dns,omitempty"`
	ServerEndpoint *string   `json:"server_endpoint,omitempty"`
	ServerPubKey   *string   `json:"server_pub_key,omitempty"`
	AllowedIPs     *[]string `json:"allowed_ips,omitempty"`
	Notes          *string   `json:"notes,omitempty"`
	Keepalive      *int      `json:"keepalive,omitempty"`
}

func (s *Server) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req keyUpdateReq
	if !readJSON(w, r, &req) {
		return
	}
	cfg := s.configSnapshot()
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	e, _ := s.findEntry(entries, id)
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if req.PublicKey != "" && req.PublicKey != e.PublicKey {
		writeErr(w, http.StatusBadRequest, "public key cannot be changed; create a new entry")
		return
	}
	newIface := sanitizeIface(req.Iface)
	if req.Iface != "" && newIface == "" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	if newIface != "" && newIface != firstNonEmpty(e.Iface, cfg.WG.DefaultIface) {
		if err := s.requirePeerUnloaded(e); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	ifaceChanged := newIface != "" && newIface != e.Iface
	endpoint := e.ServerEndpoint
	if req.ServerEndpoint != nil {
		endpoint = strings.TrimSpace(*req.ServerEndpoint)
	} else if ifaceChanged {
		endpoint = ""
	}
	if ifaceChanged && endpoint == "" {
		var err error
		endpoint, err = s.defaultEndpointForIface(newIface)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	e.Name = firstNonEmpty(req.Name, e.Name)
	if newIface != "" {
		e.Iface = newIface
	}
	if req.Address != nil {
		e.Address = *req.Address
	}
	if req.DNS != nil {
		e.DNS = *req.DNS
	}
	e.ServerEndpoint = endpoint
	if req.ServerPubKey != nil {
		e.ServerPubKey = strings.TrimSpace(*req.ServerPubKey)
	}
	if req.AllowedIPs != nil {
		e.AllowedIPs = *req.AllowedIPs
	}
	if req.Keepalive != nil && *req.Keepalive >= 0 {
		e.Keepalive = *req.Keepalive
	}
	if req.Notes != nil {
		e.Notes = *req.Notes
	}
	if err := validateVaultEntry(e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.addressConflict(e, entries); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	e.UpdatedAt = nowUTC()

	// 私钥仅在原值为空时允许补录；PSK 省略保持，空字符串清除。
	if req.PrivateKey != "" {
		if err := config.ValidateKey(req.PrivateKey); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid private_key: "+err.Error())
			return
		}
		if wg.PublicKeyFromPrivate(req.PrivateKey) != e.PublicKey {
			writeErr(w, http.StatusBadRequest, "private_key does not match public_key")
			return
		}
		if e.PrivateKeyEnc != "" {
			writeErr(w, http.StatusConflict, "private key already set; it cannot be replaced")
			return
		}
		enc, err := s.store.Encrypt([]byte(req.PrivateKey))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt secret")
			return
		}
		e.PrivateKeyEnc = enc
	}
	if req.PresharedKey != nil && *req.PresharedKey == "" {
		e.PresharedKeyEnc = ""
	} else if req.PresharedKey != nil {
		if err := config.ValidateKey(*req.PresharedKey); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid preshared_key: "+err.Error())
			return
		}
		enc, err := s.store.Encrypt([]byte(*req.PresharedKey))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt secret")
			return
		}
		e.PresharedKeyEnc = enc
	}
	if err := s.store.SaveVault(entries); err != nil {
		writeErr(w, http.StatusInternalServerError, "save vault")
		return
	}
	s.Audit(r, "keys.update", e.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleKeyDelete removes a vault entry from persistent and runtime state.
func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cfg := s.configSnapshot()

	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	e, idx := s.findEntry(entries, id)
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	resp := map[string]any{"ok": true}
	iface := firstNonEmpty(sanitizeIface(e.Iface), cfg.WG.DefaultIface)
	s.removePeerFromConfig(resp, e.PublicKey, iface)
	configError, _ := resp["config_error"].(string)
	applyError, _ := resp["apply_error"].(string)
	applyFailed := resp["apply_error"] != nil
	failure := firstNonEmpty(configError, applyError)
	if failure != "" {
		e.PendingApply = e.PendingApply || applyFailed
		if err := s.store.SaveVault(entries); err != nil {
			writeErr(w, http.StatusInternalServerError, "peer removal failed; vault retained but pending state could not be saved")
			return
		}
		resp["error"] = "peer removal failed; vault entry retained: " + failure
		writeJSON(w, http.StatusConflict, resp)
		return
	}

	entries = append(entries[:idx], entries[idx+1:]...)
	if err := s.store.SaveVault(entries); err != nil {
		writeErr(w, http.StatusInternalServerError, "save vault")
		return
	}
	s.Audit(r, "keys.delete", e.Name)
	writeJSON(w, http.StatusOK, resp)
}

// handleKeyUnload removes only the peer configuration, retaining the vault entry.
func (s *Server) handleKeyUnload(w http.ResponseWriter, r *http.Request) {
	cfg := s.configSnapshot()
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	e, _ := s.findEntry(entries, r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	iface := firstNonEmpty(sanitizeIface(e.Iface), cfg.WG.DefaultIface)
	resp := map[string]any{"iface": iface}
	s.removePeerFromConfig(resp, e.PublicKey, iface)
	applyFailed := resp["apply_error"] != nil
	applied, _ := resp["applied"].(bool)
	if applyFailed || applied {
		e.PendingApply = applyFailed
		if err := s.store.SaveVault(entries); err != nil {
			resp["save_warning"] = err.Error()
		}
	}
	s.Audit(r, "keys.unload", e.Name+" -> "+iface)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) removePeerFromConfig(resp map[string]any, publicKey, iface string) {
	confDir := s.confDir()
	s.confMu.Lock()
	defer s.confMu.Unlock()
	path := filepath.Join(confDir, iface+".conf")
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		// There is no file to sync. Remove only this runtime peer, if present;
		// never rebuild a config from runtime state.
		running, queryErr := s.runtimePeers()
		if queryErr != nil {
			resp["config_error"] = queryErr.Error()
			return
		}
		if running[iface][publicKey] {
			setApplyResult(resp, s.wg.SetPeerRemove(iface, publicKey))
			return
		}
		resp["config_removed"] = false
		resp["applied"] = true
		return
	case err != nil:
		resp["config_error"] = err.Error()
		return
	}
	conf, perr := config.Parse(string(raw))
	if perr != nil {
		resp["config_error"] = "parse failed: " + perr.Error()
		return
	}
	removed := conf.RemovePeer(publicKey)
	if removed {
		if _, err := writeConfigFile(path, conf.Render()); err != nil {
			resp["config_error"] = err.Error()
			return
		}
	}
	resp["config_removed"] = removed

	setApplyResult(resp, s.applyPeerRemoval(iface, publicKey, true))
}

// Caller holds confMu. An absent interface already satisfies an unload: do
// not turn a successful persistent removal into an endless syncconf retry.
func (s *Server) applyPeerRemoval(iface, publicKey string, confExists bool) error {
	running, err := s.runtimePeers()
	if err != nil {
		return err
	}
	peers, exists := running[iface]
	if !exists {
		return nil
	}
	if confExists {
		return s.wg.SyncConf(iface)
	}
	if peers[publicKey] {
		return s.wg.SetPeerRemove(iface, publicKey)
	}
	return nil
}

func setApplyResult(resp map[string]any, err error) {
	if err == nil {
		resp["applied"] = true
		return
	}
	resp["apply_error"] = err.Error()
}

// Request-local runtime snapshot. An empty peer set means a running interface;
// a missing interface is stopped.
func (s *Server) runtimePeers() (map[string]map[string]bool, error) {
	out, err := s.wg.ShowAllDump()
	if err != nil {
		return nil, err
	}
	ifaces, err := wg.ParseDump(out)
	if err != nil {
		return nil, err
	}
	running := make(map[string]map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		peers := make(map[string]bool, len(iface.Peers))
		for _, peer := range iface.Peers {
			peers[peer.PublicKey] = true
		}
		running[iface.Name] = peers
	}
	return running, nil
}

func (s *Server) keyEndpointDefaults() (host, defaultIface, confDir string) {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.Defaults.ServerEndpoint, s.cfg.WG.DefaultIface, s.cfg.WG.ConfDir
}

func (s *Server) defaultEndpointForIface(iface string) (string, error) {
	host, defaultIface, confDir := s.keyEndpointDefaults()
	iface = firstNonEmpty(sanitizeIface(iface), defaultIface)
	if iface == "" {
		return "", fmt.Errorf("interface is required to resolve server endpoint")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil
	}
	raw, err := os.ReadFile(filepath.Join(confDir, iface+".conf"))
	if err != nil {
		return "", fmt.Errorf("read interface config: %w", err)
	}
	conf, err := config.Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("parse interface config: %w", err)
	}
	if conf.Interface.ListenPort <= 0 {
		return "", fmt.Errorf("interface config is missing ListenPort")
	}
	return endpointWithPort(host, conf.Interface.ListenPort), nil
}

// --- auto address assignment ---------------------------------------------------

// handleNextAddress suggests an address not used by this interface's config or vault.
func (s *Server) handleNextAddress(w http.ResponseWriter, r *http.Request) {
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	s.confMu.Lock()
	defer s.confMu.Unlock()

	serverHost, defaultIface, confDir := s.keyEndpointDefaults()
	iface := sanitizeIface(r.URL.Query().Get("iface"))
	iface = firstNonEmpty(iface, defaultIface)
	path := filepath.Join(confDir, iface+".conf")

	subnets := []netip.Prefix{}
	used := []netip.Prefix{}
	mark := func(list []string) {
		used = appendUsedPrefixes(used, list)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "read interface config: "+err.Error())
		return
	}
	conf, err := config.Parse(string(raw))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "parse interface config: "+err.Error())
		return
	}
	if serverHost != "" && conf.Interface.ListenPort <= 0 {
		writeErr(w, http.StatusBadRequest, "interface config is missing ListenPort")
		return
	}
	for _, a := range conf.Interface.Address {
		if p, err := netip.ParsePrefix(a); err == nil {
			subnets = append(subnets, p.Masked())
			addr := p.Addr()
			used = append(used, netip.PrefixFrom(addr, addr.BitLen()))
		} else if addr, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			used = append(used, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	for _, peer := range conf.Peers {
		mark(peer.AllowedIPs)
	}
	out, err := s.wg.ShowAllDump()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query runtime addresses: "+err.Error())
		return
	}
	running, err := wg.ParseDump(out)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "parse runtime addresses: "+err.Error())
		return
	}
	for _, current := range running {
		if current.Name == iface {
			for _, peer := range current.Peers {
				mark(peer.AllowedIPs)
			}
		}
	}
	for _, e := range entries {
		if firstNonEmpty(sanitizeIface(e.Iface), defaultIface) == iface {
			mark(e.Address)
		}
	}

	suggestion := ""
	for _, sn := range subnets {
		if ip := nextFreeHost(sn, used); ip.IsValid() {
			bits := "32"
			if ip.Is6() {
				bits = "128"
			}
			suggestion = ip.String() + "/" + bits
			break
		}
	}

	serverSubnets := []string{}
	for _, sn := range subnets {
		serverSubnets = append(serverSubnets, sn.String())
	}
	serverEndpoint := ""
	if serverHost != "" {
		serverEndpoint = endpointWithPort(serverHost, conf.Interface.ListenPort)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"address":         suggestion,
		"server_subnets":  serverSubnets,
		"server_endpoint": serverEndpoint,
	})
}

// endpointWithPort keeps the configured server host and applies the selected
// interface's ListenPort to the client-facing Endpoint.
func endpointWithPort(endpoint string, port int) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || port <= 0 {
		return endpoint
	}

	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	} else if strings.Count(endpoint, ":") == 1 {
		host = strings.SplitN(endpoint, ":", 2)[0]
	} else {
		host = strings.Trim(endpoint, "[]")
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// nextFreeHost returns the first unused host address inside sn
// (starting right after the network address). The IPv4 broadcast
// address of the subnet is excluded.
func nextFreeHost(sn netip.Prefix, used []netip.Prefix) netip.Addr {
	cur := sn.Addr().Next()

	var broadcast netip.Addr
	if sn.Addr().Is4() && sn.Bits() <= 30 {
		a := sn.Addr().As4()
		m := net.CIDRMask(sn.Bits(), 32)
		var b [4]byte
		for i := range b {
			b[i] = a[i] | ^m[i]
		}
		broadcast = netip.AddrFrom4(b)
	}

	for sn.Contains(cur) {
		skipped := false
		for _, prefix := range used {
			if prefix.Contains(cur) {
				cur = nextAfterPrefix(prefix)
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}
		if cur != broadcast {
			return cur
		}
		cur = cur.Next()
	}
	return netip.Addr{}
}

func nextAfterPrefix(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	if addr.Is4() {
		bytes := addr.As4()
		for bit := prefix.Bits(); bit < 32; bit++ {
			bytes[bit/8] |= 1 << (7 - bit%8)
		}
		return netip.AddrFrom4(bytes).Next()
	}
	bytes := addr.As16()
	for bit := prefix.Bits(); bit < 128; bit++ {
		bytes[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom16(bytes).Next()
}

// --- client config generation ----------------------------------------------------

func (s *Server) resolveServerPubKey(e *store.VaultEntry, ifaceHint string) (string, error) {
	if e.ServerPubKey != "" {
		return e.ServerPubKey, nil
	}
	cfg := s.configSnapshot()
	ifaceHint = firstNonEmpty(sanitizeIface(ifaceHint), cfg.WG.DefaultIface)

	// 1) 运行中的接口
	out, err := s.wg.ShowAllDump()
	if err == nil {
		ifaces, perr := wg.ParseDump(out)
		if perr == nil {
			for _, ifc := range ifaces {
				if ifc.Name == ifaceHint && ifc.PublicKey != "" {
					return ifc.PublicKey, nil
				}
			}
		}
	}

	// 2) 配置文件中的私钥推导（接口未运行时）
	if raw, ferr := os.ReadFile(filepath.Join(cfg.WG.ConfDir, ifaceHint+".conf")); ferr == nil {
		if conf, perr := config.Parse(string(raw)); perr == nil && conf.Interface.PrivateKey != "" {
			pub := wg.PublicKeyFromPrivate(conf.Interface.PrivateKey)
			if pub != "" {
				return pub, nil
			}
		}
	}
	return "", fmt.Errorf("cannot resolve public key of %s: not running and no PrivateKey in config", ifaceHint)
}

// Caller holds confMu. Addresses are reservations for host or network ranges.
func (s *Server) addressConflict(e *store.VaultEntry, entries []*store.VaultEntry) error {
	cfg := s.configSnapshot()
	requested := make([]addressReservation, 0, len(e.Address))
	for _, value := range e.Address {
		prefix, ok := addressPrefix(value)
		if !ok {
			continue // validateVaultEntry reports malformed input first
		}
		if prior, ok := findReservationOverlap(prefix, requested); ok {
			return fmt.Errorf("client address %q overlaps %q", value, prior.value)
		}
		requested = append(requested, addressReservation{prefix: prefix, value: value})
	}
	if len(requested) == 0 {
		return nil
	}
	iface := firstNonEmpty(sanitizeIface(e.Iface), cfg.WG.DefaultIface)
	out, err := s.wg.ShowAllDump()
	if err != nil {
		return fmt.Errorf("query runtime addresses: %w", err)
	}
	running, err := wg.ParseDump(out)
	if err != nil {
		return fmt.Errorf("parse runtime addresses: %w", err)
	}
	for _, current := range running {
		if current.Name != iface {
			continue
		}
		for _, peer := range current.Peers {
			if peer.PublicKey == e.PublicKey {
				continue
			}
			if candidate, value, ok := findValueOverlap(requested, peer.AllowedIPs); ok {
				return fmt.Errorf("client address %q overlaps runtime peer address %q", candidate.value, value)
			}
		}
	}
	path := filepath.Join(cfg.WG.ConfDir, iface+".conf")
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read interface config: %w", err)
	}
	if err == nil {
		conf, err := config.Parse(string(raw))
		if err != nil {
			return fmt.Errorf("parse interface config: %w", err)
		}
		for _, value := range conf.Interface.Address {
			prefix, ok := addressPrefix(value)
			if !ok {
				continue
			}
			addr, err := netip.ParsePrefix(value)
			if err == nil {
				prefix = netip.PrefixFrom(addr.Addr(), addr.Addr().BitLen())
			}
			if candidate, ok := findReservationOverlap(prefix, requested); ok {
				return fmt.Errorf("client address %q overlaps server address %q", candidate.value, value)
			}
		}
		for _, peer := range conf.Peers {
			if peer.PublicKey == e.PublicKey {
				continue
			}
			if candidate, value, ok := findValueOverlap(requested, peer.AllowedIPs); ok {
				return fmt.Errorf("client address %q overlaps configured peer address %q", candidate.value, value)
			}
		}
	}
	for _, other := range entries {
		if other.ID == e.ID || firstNonEmpty(sanitizeIface(other.Iface), cfg.WG.DefaultIface) != iface {
			continue
		}
		if candidate, value, ok := findValueOverlap(requested, other.Address); ok {
			return fmt.Errorf("client address %q overlaps vault address %q", candidate.value, value)
		}
	}
	return nil
}

type addressReservation struct {
	prefix netip.Prefix
	value  string
}

func findReservationOverlap(prefix netip.Prefix, reservations []addressReservation) (addressReservation, bool) {
	for _, reservation := range reservations {
		if prefixesOverlap(prefix, reservation.prefix) {
			return reservation, true
		}
	}
	return addressReservation{}, false
}

func findValueOverlap(reservations []addressReservation, values []string) (addressReservation, string, bool) {
	for _, value := range values {
		prefix, ok := addressPrefix(value)
		if !ok {
			continue
		}
		if reservation, ok := findReservationOverlap(prefix, reservations); ok {
			return reservation, value, true
		}
	}
	return addressReservation{}, "", false
}

func addressPrefix(value string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func appendUsedPrefixes(dst []netip.Prefix, values []string) []netip.Prefix {
	for _, value := range values {
		if prefix, ok := addressPrefix(strings.TrimSpace(value)); ok {
			dst = append(dst, prefix)
		}
	}
	return dst
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}

func renderClientConfig(e *store.VaultEntry, privateKey, serverPub, presharedKey string, fallbackCIDRs []string) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	if len(e.Address) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(e.Address, ", "))
	}
	if len(e.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(e.DNS, ", "))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
	if presharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", presharedKey)
	}
	switch {
	case len(e.AllowedIPs) > 0:
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(e.AllowedIPs, ", "))
	case len(fallbackCIDRs) > 0:
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(fallbackCIDRs, ", "))
	default:
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	}
	if e.ServerEndpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", e.ServerEndpoint)
	}
	if e.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", e.Keepalive)
	}
	return b.String()
}

// serverSubnets returns the masked [Interface] Address prefixes of the
// default config file (e.g. 10.10.0.0/24).
func (s *Server) serverSubnets(iface string) []string {
	cfg := s.configSnapshot()
	iface = firstNonEmpty(sanitizeIface(iface), cfg.WG.DefaultIface)
	raw, err := os.ReadFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"))
	if err != nil {
		return nil
	}
	conf, err := config.Parse(string(raw))
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range conf.Interface.Address {
		if p, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
			out = append(out, p.Masked().String())
		}
	}
	return out
}

func (s *Server) clientConfigFor(w http.ResponseWriter, id string) (*store.VaultEntry, string, bool) {
	cfg := s.configSnapshot()
	entries, ok := s.lockVault(w)
	if !ok {
		return nil, "", false
	}
	defer s.vaultMu.Unlock()
	s.confMu.Lock()
	defer s.confMu.Unlock()
	e, _ := s.findEntry(entries, id)
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return nil, "", false
	}
	if e.PrivateKeyEnc == "" {
		writeErr(w, http.StatusBadRequest, "no private key stored for this peer")
		return nil, "", false
	}
	privRaw, err := s.store.Decrypt(e.PrivateKeyEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "decrypt private key")
		return nil, "", false
	}
	ifaceHint := firstNonEmpty(e.Iface, cfg.WG.DefaultIface)
	serverPub, err := s.resolveServerPubKey(e, ifaceHint)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return nil, "", false
	}
	psk := ""
	if e.PresharedKeyEnc != "" {
		raw, err := s.store.Decrypt(e.PresharedKeyEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "decrypt preshared key")
			return nil, "", false
		}
		psk = string(raw)
	}
	return e, renderClientConfig(e, string(privRaw), serverPub, psk, s.serverSubnets(e.Iface)), true
}

func (s *Server) handleClientConfig(w http.ResponseWriter, r *http.Request) {
	e, conf, ok := s.clientConfigFor(w, r.PathValue("id"))
	if !ok {
		return
	}
	fname := sanitizeDownloadName(e.Name)
	s.Audit(r, "keys.client-config.download", e.Name)
	noStore(w)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", fname+".conf"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(conf))
}

func (s *Server) handleClientQR(w http.ResponseWriter, r *http.Request) {
	_, conf, ok := s.clientConfigFor(w, r.PathValue("id"))
	if !ok {
		return
	}
	png, err := qrcode.Encode(conf, qrcode.Medium, 512)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "render QR")
		return
	}
	s.Audit(r, "keys.qrcode", "")
	noStore(w)
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// --- small helpers -------------------------------------------------------------

// sanitizeIface validates an interface name; returns "" when invalid/empty.
func sanitizeIface(name string) string {
	name = strings.TrimSpace(name)
	if !config.ValidIfaceName(name) {
		return ""
	}
	return name
}

// Validate persisted client fields before they can reach either config renderer.
func validateVaultEntry(e *store.VaultEntry) error {
	if err := validateAddressValues("address", e.Address); err != nil {
		return err
	}
	if err := validateAddressValues("allowed_ips", e.AllowedIPs); err != nil {
		return err
	}
	for _, value := range e.DNS {
		if value == "" || validateEndpointHost(value) != nil {
			return fmt.Errorf("invalid DNS: %q", value)
		}
	}
	if e.ServerEndpoint != "" {
		host, port, err := net.SplitHostPort(e.ServerEndpoint)
		n, nerr := strconv.Atoi(port)
		if err != nil || nerr != nil || n < 1 || n > 65535 || host == "" || validateEndpointHost(host) != nil {
			return fmt.Errorf("invalid server_endpoint; use host:port")
		}
	}
	if e.ServerPubKey != "" {
		if err := config.ValidateKey(e.ServerPubKey); err != nil {
			return fmt.Errorf("invalid server_pub_key: %w", err)
		}
	}
	if e.Keepalive < 0 || e.Keepalive > 65535 {
		return fmt.Errorf("keepalive must be between 0 and 65535")
	}
	return nil
}

func validateAddressValues(field string, values []string) error {
	for _, value := range values {
		if strings.Contains(value, "/") {
			if _, err := netip.ParsePrefix(value); err == nil {
				continue
			}
		} else if _, err := netip.ParseAddr(value); err == nil {
			continue
		}
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	return nil
}

// Caller holds vaultMu and confMu. Moving a loaded identity would orphan its
// old peer. Require an explicit successful unload before changing interfaces.
func (s *Server) requirePeerUnloaded(e *store.VaultEntry) error {
	cfg := s.configSnapshot()
	if e.PendingApply {
		return fmt.Errorf("apply the pending configuration before changing interfaces")
	}
	iface := firstNonEmpty(e.Iface, cfg.WG.DefaultIface)
	raw, err := os.ReadFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"))
	if err == nil {
		conf, err := config.Parse(string(raw))
		if err != nil {
			return fmt.Errorf("cannot verify old configuration: %w", err)
		}
		for _, p := range conf.Peers {
			if p.PublicKey == e.PublicKey {
				return fmt.Errorf("unload the peer before changing interfaces")
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	running, err := s.runtimePeers()
	if err != nil {
		return fmt.Errorf("cannot verify runtime state: %w", err)
	}
	if running[iface][e.PublicKey] {
		return fmt.Errorf("unload the running peer before changing interfaces")
	}
	return nil
}

// Retry application only: never reverse the desired state or rewrite the file.
func (s *Server) handleKeyApply(w http.ResponseWriter, r *http.Request) {
	cfg := s.configSnapshot()
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	e, _ := s.findEntry(entries, r.PathValue("id"))
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	iface := firstNonEmpty(e.Iface, cfg.WG.DefaultIface)
	raw, err := os.ReadFile(filepath.Join(cfg.WG.ConfDir, iface+".conf"))
	if os.IsNotExist(err) {
		// With no persistent config the intended peer state is absent. Remove
		// only that runtime peer rather than synthesizing an interface file.
		err = s.applyPeerRemoval(iface, e.PublicKey, false)
	} else if err == nil {
		var conf *config.Config
		if conf, err = config.Parse(string(raw)); err == nil {
			loaded := false
			for _, peer := range conf.Peers {
				if peer.PublicKey == e.PublicKey {
					loaded = true
					break
				}
			}
			if loaded {
				err = s.wg.SyncConf(iface)
			} else {
				err = s.applyPeerRemoval(iface, e.PublicKey, true)
			}
		}
	}
	resp := map[string]any{"iface": iface}
	e.PendingApply = err != nil
	setApplyResult(resp, err)
	if err := s.store.SaveVault(entries); err != nil {
		resp["save_warning"] = err.Error()
	}
	s.Audit(r, "keys.apply", e.Name+" -> "+iface)
	writeJSON(w, http.StatusOK, resp)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func sanitizeDownloadName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, name)
	if name == "" || name == "." || name == ".." {
		return "peer-" + fmt.Sprint(time.Now().Unix())
	}
	return name
}
