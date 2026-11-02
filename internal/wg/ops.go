package wg

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/yq/wireguard-manager/internal/config"
)

// Backend abstracts the wireguard-tools CLI so tests and demo mode can fake it.
type Backend interface {
	ShowAllDump() (string, error)
	SetPeerRemove(iface, publicKey string) error
	QuickUp(iface string) error
	QuickDown(iface string) error
	SyncConf(iface string) error
}

// ShowAllDump returns raw `wg show all dump` output.
func (r *Runner) ShowAllDump() (string, error) {
	return r.run(r.WGBin, "show", "all", "dump")
}

// SetPeerRemove removes a peer from a running interface:
// `wg set <iface> peer <publicKey> remove`.
func (r *Runner) SetPeerRemove(iface, publicKey string) error {
	_, err := r.run(r.WGBin, "set", iface, "peer", publicKey, "remove")
	return err
}

// QuickUp brings iface up via wg-quick.
func (r *Runner) QuickUp(iface string) error {
	path, err := r.configPath(iface)
	if err != nil {
		return err
	}
	_, err = r.run(r.QuickBin, "up", path)
	return err
}

// QuickDown tears iface down via wg-quick.
func (r *Runner) QuickDown(iface string) error {
	path, err := r.configPath(iface)
	if err != nil {
		return err
	}
	_, err = r.run(r.QuickBin, "down", path)
	return err
}

// SyncConf live-applies the on-disk config:
// `wg syncconf <iface> <(wg-quick strip <iface>)>`.
func (r *Runner) SyncConf(iface string) error {
	path, err := r.configPath(iface)
	if err != nil {
		return err
	}
	stripped, err := r.run(r.QuickBin, "strip", path)
	if err != nil {
		return fmt.Errorf("strip config: %w", err)
	}
	f, err := os.CreateTemp("", "wgm-syncconf-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(stripped); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = r.run(r.WGBin, "syncconf", iface, f.Name())
	return err
}

// Validate the actual file before any wg-quick operation, including down:
// legacy SaveConfig=true files must never trigger a runtime write-back.
func (r *Runner) configPath(iface string) (string, error) {
	if !config.ValidIfaceName(iface) {
		return "", fmt.Errorf("invalid interface name")
	}
	path, err := filepath.Abs(filepath.Join(r.ConfDir, iface+".conf"))
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if _, err := config.Parse(string(raw)); err != nil {
		return "", fmt.Errorf("invalid interface config: %w", err)
	}
	return path, nil
}
