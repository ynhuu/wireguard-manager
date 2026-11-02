package wg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuickAndSyncUseConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "custom-config")
	if err := os.Mkdir(confDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(confDir, "wg1.conf")
	if err := os.WriteFile(path, []byte("[Interface]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	quickLog := filepath.Join(dir, "quick.log")
	wgLog := filepath.Join(dir, "wg.log")
	quick := filepath.Join(dir, "wg-quick")
	wgBin := filepath.Join(dir, "wg")
	if err := os.WriteFile(quick, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+quickLog+"'\nprintf '[Interface]\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wgBin, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+wgLog+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := NewRunner(wgBin, quick, confDir)
	if err := r.QuickUp("wg1"); err != nil {
		t.Fatal(err)
	}
	if err := r.QuickDown("wg1"); err != nil {
		t.Fatal(err)
	}
	if err := r.SyncConf("wg1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(quickLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "up "+path+"\ndown "+path+"\nstrip "+path+"\n" {
		t.Fatalf("wrong config path: %s", raw)
	}
	raw, err = os.ReadFile(wgLog)
	if err != nil || !strings.HasPrefix(string(raw), "syncconf wg1 ") {
		t.Fatalf("wrong syncconf target: %s %v", raw, err)
	}
}

func TestQuickDownRejectsSaveConfigBeforeExecuting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wg0.conf"), []byte("[Interface]\nSaveConfig = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := NewRunner("/missing-wg", "/missing-quick", dir)
	if err := r.QuickDown("wg0"); err == nil || !strings.Contains(err.Error(), "SaveConfig") {
		t.Fatalf("unsafe config passed to wg-quick: %v", err)
	}
}
