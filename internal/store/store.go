package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

var ErrNotFound = errors.New("not found")

// Store persists YAML documents inside a data directory with 0600 perms.
type Store struct {
	dir      string
	masterMu sync.Mutex
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("protect data dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// LoadYAML reads path relative to dir into v. Returns ErrNotFound when absent.
func (s *Store) LoadYAML(name string, v any) error {
	data, err := os.ReadFile(s.path(name))
	if os.IsNotExist(err) {
		return fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return nil
}

// SaveYAML atomically writes v as YAML to name with 0600 permissions.
func (s *Store) SaveYAML(name string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	p := s.path(name)
	f, err := os.CreateTemp(s.dir, filepath.Base(p)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", name, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("protect %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", name, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("replace %s: %w", name, err)
	}
	return nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }
