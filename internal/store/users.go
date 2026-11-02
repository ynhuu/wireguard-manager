package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"
)

// User is the single administrator account persisted in users.yaml.
type User struct {
	Username          string    `yaml:"username"`
	PasswordHash      string    `yaml:"password_hash"`
	TOTPSecret        string    `yaml:"totp_secret"`
	TOTPEnabled       bool      `yaml:"totp_enabled"`
	PendingTOTPSecret string    `yaml:"pending_totp_secret,omitempty"`
	CreatedAt         time.Time `yaml:"created_at"`
}

// GetUser loads the admin account; returns (nil, nil) when not initialized.
func (s *Store) GetUser() (*User, error) {
	var u User
	err := s.LoadYAML("users.yaml", &u)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// SaveUser writes the admin account.
func (s *Store) SaveUser(u *User) error {
	return s.SaveYAML("users.yaml", u)
}

// --- master key -------------------------------------------------------------

func (s *Store) masterKeyPath() string { return s.path("master.key") }

// MasterKey returns the vault encryption key, generating it on first use.
func (s *Store) MasterKey() ([]byte, error) {
	s.masterMu.Lock()
	defer s.masterMu.Unlock()
	if b, err := os.ReadFile(s.masterKeyPath()); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("master.key must contain exactly 32 bytes; restore it from backup")
		}
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read master.key: %w", err)
	}
	entries, err := s.LoadVault()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.PrivateKeyEnc != "" || e.PresharedKeyEnc != "" {
			return nil, fmt.Errorf("master.key is missing for an existing encrypted vault; restore it from backup")
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.dir, ".master-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	// Link installs a fully written file without ever replacing an existing key,
	// even if another Store/process initialized it concurrently.
	if err := os.Link(f.Name(), s.masterKeyPath()); err != nil {
		if os.IsExist(err) {
			b, readErr := os.ReadFile(s.masterKeyPath())
			if readErr == nil && len(b) == 32 {
				return b, nil
			}
		}
		return nil, fmt.Errorf("create master.key: %w", err)
	}
	return key, nil
}

// --- vault ------------------------------------------------------------------

// VaultEntry stores one WireGuard client/peer identity. Secrets are
// AES-256-GCM encrypted at rest with the master key.
type VaultEntry struct {
	ID              string    `yaml:"id" json:"id"`
	Name            string    `yaml:"name" json:"name"`
	PublicKey       string    `yaml:"public_key" json:"public_key"`
	PrivateKeyEnc   string    `yaml:"private_key_enc,omitempty" json:"-"`
	PresharedKeyEnc string    `yaml:"preshared_key_enc,omitempty" json:"-"`
	Iface           string    `yaml:"iface,omitempty" json:"iface,omitempty"` // target interface (e.g. wg0)
	PendingApply    bool      `yaml:"pending_apply,omitempty" json:"pending_apply"`
	Address         []string  `yaml:"address,omitempty" json:"address"` // client-side tunnel addresses
	DNS             []string  `yaml:"dns,omitempty" json:"dns"`         // client-side DNS
	ServerEndpoint  string    `yaml:"server_endpoint,omitempty" json:"server_endpoint,omitempty"`
	ServerPubKey    string    `yaml:"server_pub_key,omitempty" json:"server_pub_key,omitempty"`
	AllowedIPs      []string  `yaml:"allowed_ips,omitempty" json:"allowed_ips"`
	Keepalive       int       `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`
	Notes           string    `yaml:"notes,omitempty" json:"notes,omitempty"`
	CreatedAt       time.Time `yaml:"created_at" json:"created_at"`
	UpdatedAt       time.Time `yaml:"updated_at" json:"updated_at"`
}

type vaultFile struct {
	Entries []*VaultEntry `yaml:"entries"`
}

func (s *Store) LoadVault() ([]*VaultEntry, error) {
	var f vaultFile
	err := s.LoadYAML("vault.yaml", &f)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if f.Entries == nil {
		f.Entries = []*VaultEntry{}
	}
	entries := f.Entries[:0]
	for _, entry := range f.Entries {
		if entry == nil {
			continue
		}
		if entry.Address == nil {
			entry.Address = []string{}
		}
		if entry.DNS == nil {
			entry.DNS = []string{}
		}
		if entry.AllowedIPs == nil {
			entry.AllowedIPs = []string{}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *Store) SaveVault(entries []*VaultEntry) error {
	return s.SaveYAML("vault.yaml", vaultFile{Entries: entries})
}

// Encrypt seals plaintext with AES-256-GCM; output is base64(nonce||ciphertext).
func (s *Store) Encrypt(plaintext []byte) (string, error) {
	key, err := s.MasterKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt.
func (s *Store) Decrypt(encoded string) ([]byte, error) {
	key, err := s.MasterKey()
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}
