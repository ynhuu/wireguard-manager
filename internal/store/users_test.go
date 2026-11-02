package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMasterKeyNeverReplacesDamagedKey(t *testing.T) {
	for _, size := range []int{0, 7, 31, 33} {
		t.Run(fmt.Sprintf("length-%d", size), func(t *testing.T) {
			st, err := New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Repeat([]byte{42}, size)
			if err := os.WriteFile(st.masterKeyPath(), original, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := st.MasterKey(); err == nil {
				t.Fatal("damaged key accepted or replaced")
			}
			raw, err := os.ReadFile(st.masterKeyPath())
			if err != nil || !bytes.Equal(raw, original) {
				t.Fatal("damaged key overwritten")
			}
		})
	}
}

func TestMissingMasterKeyForEncryptedVaultIsError(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveVault([]*VaultEntry{{ID: "existing", PrivateKeyEnc: "existing-ciphertext"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MasterKey(); err == nil {
		t.Fatal("generated replacement key for encrypted vault")
	}
	if _, err := os.Stat(st.masterKeyPath()); !os.IsNotExist(err) {
		t.Fatalf("key created: %v", err)
	}
}

func TestMasterKeyReadErrorIsNotReplaced(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(st.masterKeyPath(), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MasterKey(); err == nil {
		t.Fatal("read failure ignored")
	}
	info, err := os.Stat(st.masterKeyPath())
	if err != nil || !info.IsDir() {
		t.Fatal("unreadable key path replaced")
	}
}

func TestConcurrentMasterKeyInitialization(t *testing.T) {
	dir := t.TempDir()
	const count = 12
	keys := make([][]byte, count)
	errs := make([]error, count)
	var group sync.WaitGroup
	for i := range keys {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			st, err := New(dir)
			if err != nil {
				errs[i] = err
				return
			}
			keys[i], errs[i] = st.MasterKey()
		}(i)
	}
	group.Wait()
	for i := range keys {
		if errs[i] != nil || len(keys[i]) != 32 || !bytes.Equal(keys[i], keys[0]) {
			t.Fatalf("inconsistent key at %d: %v", i, errs[i])
		}
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wrong key permissions")
	}
}
