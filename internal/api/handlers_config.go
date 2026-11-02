package api

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/wg"
)

// handleConfFiles lists *.conf files in the WireGuard config directory.
func (s *Server) handleConfFiles(w http.ResponseWriter, r *http.Request) {
	cfg := s.configSnapshot()
	s.confMu.Lock()
	defer s.confMu.Unlock()
	entries, err := os.ReadDir(cfg.WG.ConfDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusOK, map[string]any{"files": []string{}, "conf_dir": cfg.WG.ConfDir})
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && sanitizeFileName(e.Name()) == nil {
			files = append(files, e.Name())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "conf_dir": cfg.WG.ConfDir})
}

type confReadResp struct {
	File       string         `json:"file"`
	Content    string         `json:"content"`
	Parsed     *config.Config `json:"parsed,omitempty"`
	ParseError string         `json:"parse_error,omitempty"`
	Revision   string         `json:"revision"`
}

func (s *Server) confPath(file string) (string, bool) {
	if sanitizeFileName(file) != nil {
		return "", false
	}
	return filepath.Join(s.confDir(), file), true
}

func (s *Server) handleConfRead(w http.ResponseWriter, r *http.Request) {
	s.confMu.Lock()
	defer s.confMu.Unlock()
	file := r.URL.Query().Get("file")
	path, ok := s.confPath(file)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid file name")
		return
	}
	data, err := os.ReadFile(path)
	resp := confReadResp{File: file}
	rawContent := string(data)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// An absent file is a valid empty editor state.
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	default:
		resp.Content = redactConfigPrivateKey(rawContent)
	}
	resp.Revision = configRevision(data)
	if cfg, perr := config.Parse(rawContent); perr != nil {
		resp.ParseError = perr.Error()
	} else if rawContent != "" {
		cfg.Interface.PrivateKey = ""
		resp.Parsed = cfg
	}
	writeJSON(w, http.StatusOK, resp)
}

type confWriteReq struct {
	File     string  `json:"file"`
	Content  string  `json:"content"`
	Create   bool    `json:"create"`             // reject an existing file when creating
	Revision *string `json:"revision,omitempty"` // optimistic concurrency for editors
}

// handleConfWrite validates, backs up, then atomically writes a config file.
func (s *Server) handleConfWrite(w http.ResponseWriter, r *http.Request) {
	var req confWriteReq
	if !readJSON(w, r, &req) {
		return
	}
	cfg := s.configSnapshot()
	if sanitizeFileName(req.File) != nil {
		writeErr(w, http.StatusBadRequest, "invalid file name")
		return
	}
	path := filepath.Join(cfg.WG.ConfDir, req.File)
	entries, ok := s.lockVault(w)
	if !ok {
		return
	}
	defer s.vaultMu.Unlock()
	s.confMu.Lock()
	defer s.confMu.Unlock()
	if req.Create {
		if _, err := os.Stat(path); err == nil {
			writeErr(w, http.StatusConflict, "config file already exists")
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if req.Revision != nil && !req.Create {
		raw, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if configRevision(raw) != *req.Revision {
			writeErr(w, http.StatusConflict, "config changed; reload it before saving")
			return
		}
	}
	content, err := restoreConfigPrivateKey(path, req.Content)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	parsed, perr := config.Parse(content)
	if perr != nil {
		s.Audit(r, "conf.write.reject", req.File+": "+perr.Error())
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":       "validation failed",
			"parse_error": perr.Error(),
		})
		return
	}
	iface := strings.TrimSuffix(req.File, ".conf")
	for _, peer := range parsed.Peers {
		for _, entry := range entries {
			if entry.PublicKey == peer.PublicKey || firstNonEmpty(entry.Iface, cfg.WG.DefaultIface) != iface {
				continue
			}
			for _, value := range peer.AllowedIPs {
				prefix, ok := addressPrefix(value)
				if !ok {
					continue
				}
				for _, reserved := range entry.Address {
					if other, ok := addressPrefix(reserved); ok && prefixesOverlap(prefix, other) {
						writeErr(w, http.StatusConflict, "config peer address overlaps a vault reservation")
						return
					}
				}
			}
		}
	}
	if err := os.MkdirAll(cfg.WG.ConfDir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := writeConfigFile(path, content); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Audit(r, "conf.write", req.File)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

const redactedPrivateKeyLine = "# WireGuard Manager: server PrivateKey hidden"

func redactConfigPrivateKey(content string) string {
	lines := strings.SplitAfter(content, "\n")
	section := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		if section != "interface" || !isConfigKey(line, "privatekey") {
			continue
		}
		ending := ""
		if strings.HasSuffix(line, "\n") {
			ending = "\n"
		}
		lines[i] = redactedPrivateKeyLine + ending
		break
	}
	return strings.Join(lines, "")
}

func restoreConfigPrivateKey(path, content string) (string, error) {
	count := strings.Count(content, redactedPrivateKeyLine)
	if count == 0 {
		return content, nil
	}
	if count != 1 {
		return "", fmt.Errorf("invalid hidden PrivateKey marker")
	}
	if key, ok := interfacePrivateKey(content); ok && key != "" {
		return strings.Replace(content, redactedPrivateKeyLine, "", 1), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot restore hidden PrivateKey: %w", err)
	}
	key, ok := interfacePrivateKey(string(raw))
	if !ok || key == "" {
		return "", fmt.Errorf("existing config has no Interface PrivateKey")
	}
	return strings.Replace(content, redactedPrivateKeyLine, "PrivateKey = "+key, 1), nil
}

func interfacePrivateKey(content string) (string, bool) {
	section := ""
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		if section != "interface" {
			continue
		}
		if key, value, ok := strings.Cut(trimmed, "="); ok && strings.EqualFold(strings.TrimSpace(key), "privatekey") {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}

func isConfigKey(line, want string) bool {
	key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
	return ok && strings.EqualFold(strings.TrimSpace(key), want)
}

// handleConfDelete removes a config file together with every backup copy.
// If the interface is currently running it is brought down first, so no
// orphaned interface survives its config.
func (s *Server) handleConfDelete(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	path, ok := s.confPath(file)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid file name")
		return
	}
	s.confMu.Lock()
	defer s.confMu.Unlock()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "file does not exist")
		} else {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	iface := strings.TrimSuffix(file, ".conf")

	resp := map[string]any{"ok": true}

	// Snapshot every target before removing anything. If the directory cannot
	// be listed or a backup cannot be read, the original set is retained.
	snapshots, err := snapshotDeleteFiles(path, file)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "prepare deletion: "+err.Error())
		return
	}

	// 运行中的接口先停止
	out, err := s.wg.ShowAllDump()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot verify interface state; config retained: "+err.Error())
		return
	}
	ifaces, err := wg.ParseDump(out)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot parse interface state; config retained: "+err.Error())
		return
	}
	stopped := false
	for _, ic := range ifaces {
		if ic.Name != iface {
			continue
		}
		if derr := s.wg.QuickDown(iface); derr != nil {
			s.Audit(r, "conf.delete.stop-fail", iface+": "+derr.Error())
			writeErr(w, http.StatusInternalServerError, "stop failed; config and backups retained: "+derr.Error())
			return
		}
		stopped = true
		break
	}

	// 清理主配置及其全部备份副本；中途失败时恢复整个集合。
	var removedBaks []string
	for _, snapshot := range snapshots {
		if err := os.Remove(snapshot.path); err != nil {
			rollbackErr := restoreDeleteFiles(snapshots)
			msg := "remove config: " + err.Error()
			if rollbackErr != nil {
				msg += "; rollback failed: " + rollbackErr.Error()
			}
			if stopped {
				if upErr := s.wg.QuickUp(iface); upErr != nil {
					msg += "; interface restore failed: " + upErr.Error()
				}
			}
			writeErr(w, http.StatusInternalServerError, msg)
			return
		}
		if snapshot.path != path {
			removedBaks = append(removedBaks, filepath.Base(snapshot.path))
		}
	}

	detail := file
	if stopped {
		detail += " (interface stopped)"
		resp["stopped"] = true
	}
	if len(removedBaks) > 0 {
		detail += fmt.Sprintf(" (+%d backup(s))", len(removedBaks))
	}
	s.Audit(r, "conf.delete", detail)
	resp["removed_backups"] = len(removedBaks)
	writeJSON(w, http.StatusOK, resp)
}

// handleConfAutoUpGet reports whether the interface auto-starts on launch.
func (s *Server) handleConfAutoUpGet(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	iface := strings.TrimSuffix(file, ".conf")
	if sanitizeFileName(file) != nil || iface == "" {
		writeErr(w, http.StatusBadRequest, "invalid file name")
		return
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	skip := slices.Contains(s.cfg.WG.AutoUpSkip, iface)
	writeJSON(w, http.StatusOK, map[string]any{"enabled": !skip})
}

// handleConfAutoUpSet toggles per-interface auto-start; persisted in app.yaml.
func (s *Server) handleConfAutoUpSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File    string `json:"file"`
		Enabled bool   `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if sanitizeFileName(req.File) != nil {
		writeErr(w, http.StatusBadRequest, "invalid file name")
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	iface := strings.TrimSuffix(req.File, ".conf")
	next := cloneAppConfig(s.cfg)
	next.WG.AutoUpSkip = slices.DeleteFunc(next.WG.AutoUpSkip, func(v string) bool { return v == iface })
	if !req.Enabled {
		next.WG.AutoUpSkip = append(next.WG.AutoUpSkip, iface)
	}
	path := filepath.Join(s.store.Dir(), "app.yaml")
	if err := next.Save(path); err != nil {
		writeErr(w, http.StatusInternalServerError, "save app.yaml: "+err.Error())
		return
	}
	*s.cfg = next
	s.Audit(r, "conf.auto-up", fmt.Sprintf("%s=%v", iface, req.Enabled))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": req.Enabled})
}

// backupFile copies path to path+".bak" (overwrites previous backup).
// Missing source is not an error; returns "" in that case.
func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	bak := path + ".bak"
	return bak, atomicReplaceFile(bak, filepath.Base(bak)+".tmp-*", data, 0o600)
}

func configRevision(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// Caller holds confMu. Validate first, retain one backup, then rename a unique
// 0600 temporary file in the same directory (no shared .tmp race).
func writeConfigFile(path, content string) (string, error) {
	if _, err := config.Parse(content); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}
	backup, err := backupFile(path)
	if err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}
	return backup, atomicReplaceFile(path, ".wgm-conf-*", []byte(content), 0o600)
}

func atomicReplaceFile(path, pattern string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type deleteFileSnapshot struct {
	path string
	data []byte
	mode os.FileMode
}

func snapshotDeleteFiles(path, file string) ([]deleteFileSnapshot, error) {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	paths := []string{path}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), file+".bak") {
			paths = append(paths, filepath.Join(filepath.Dir(path), entry.Name()))
		}
	}
	snapshots := make([]deleteFileSnapshot, 0, len(paths))
	for _, target := range paths {
		data, err := os.ReadFile(target)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(target), err)
		}
		info, err := os.Stat(target)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", filepath.Base(target), err)
		}
		snapshots = append(snapshots, deleteFileSnapshot{path: target, data: data, mode: info.Mode().Perm()})
	}
	return snapshots, nil
}

func restoreDeleteFiles(snapshots []deleteFileSnapshot) error {
	var firstErr error
	for _, snapshot := range snapshots {
		err := atomicReplaceFile(snapshot.path, ".wgm-restore-*", snapshot.data, snapshot.mode)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("restore %s: %w", filepath.Base(snapshot.path), err)
			}
		}
	}
	return firstErr
}

func restoreConfigFile(path, backup string) error {
	data, err := os.ReadFile(backup)
	if err != nil {
		return fmt.Errorf("read backup for rollback: %w", err)
	}
	info, err := os.Stat(backup)
	if err != nil {
		return fmt.Errorf("stat backup for rollback: %w", err)
	}
	return restoreDeleteFiles([]deleteFileSnapshot{{path: path, data: data, mode: info.Mode().Perm()}})
}
