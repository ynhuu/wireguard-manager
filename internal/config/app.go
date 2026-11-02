package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AppConfig is the manager's own configuration, persisted as YAML.
type AppConfig struct {
	Listen   string         `yaml:"listen"`
	DataDir  string         `yaml:"data_dir"`
	WG       WGConfig       `yaml:"wireguard"`
	Defaults DefaultsConfig `yaml:"defaults"`
}

type WGConfig struct {
	ConfDir      string `yaml:"conf_dir"`
	DefaultIface string `yaml:"default_iface"`
	WGBin        string `yaml:"wg_bin"`
	QuickBin     string `yaml:"wg_quick_bin"`
	// AutoUp starts every *.conf interface via wg-quick up on program launch.
	// Already-running interfaces are skipped. Interfaces listed in AutoUpSkip
	// are never auto-started.
	AutoUp     bool     `yaml:"auto_up"`
	AutoUpSkip []string `yaml:"auto_up_skip,omitempty"`
}

// DefaultsConfig holds values prefilled when creating peers.
type DefaultsConfig struct {
	ServerEndpoint string `yaml:"server_endpoint"`
}

// Defaults returns the default application configuration.
func Defaults() *AppConfig {
	return &AppConfig{
		Listen:  "127.0.0.1:8080",
		DataDir: "/etc/wireguard-manager",
		WG: WGConfig{
			ConfDir:      "/etc/wireguard",
			DefaultIface: "wg0",
			WGBin:        "/usr/bin/wg",
			QuickBin:     "/usr/bin/wg-quick",
			AutoUp:       true,
		},
	}
}

// Load reads the YAML config at path, creating it with defaults when absent.
// Any zero-value fields are filled with defaults.
func Load(path string) (*AppConfig, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		if err := cfg.Save(path); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("read config: %w", err)
	default:
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	cfg.fillDefaults()
	return cfg, nil
}

func (c *AppConfig) fillDefaults() {
	d := Defaults()
	if c.Listen == "" {
		c.Listen = d.Listen
	}
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.WG.ConfDir == "" {
		c.WG.ConfDir = d.WG.ConfDir
	}
	if c.WG.DefaultIface == "" {
		c.WG.DefaultIface = d.WG.DefaultIface
	}
	if c.WG.WGBin == "" {
		c.WG.WGBin = d.WG.WGBin
	}
	if c.WG.QuickBin == "" {
		c.WG.QuickBin = d.WG.QuickBin
	}
}

// Save atomically writes the config as YAML.
func (c *AppConfig) Save(path string) error {
	c.fillDefaults()
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
