package apikey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateVerifyRevoke(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	s := NewStore(path)
	key, k, err := s.Create("ci", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "fg_") || len(key) < 40 {
		t.Fatalf("weak key %q", key)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), key) {
		t.Fatal("plaintext key stored on disk")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("keys file mode = %v", fi.Mode().Perm())
	}
	if _, _, err := s.Create("ci", 0); err == nil {
		t.Fatal("duplicate name accepted")
	}

	v, err := NewVerifier(s)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := v.Verify(key); !ok || got.ID != k.ID {
		t.Fatal("valid key rejected")
	}
	if _, ok := v.Verify(key + "x"); ok {
		t.Fatal("tampered key accepted")
	}
	if _, ok := v.Verify("not-a-key"); ok {
		t.Fatal("garbage accepted")
	}

	if _, err := s.Revoke(k.ID); err != nil {
		t.Fatal(err)
	}
	v2, _ := NewVerifier(s)
	if _, ok := v2.Verify(key); ok {
		t.Fatal("revoked key accepted")
	}
}

func TestExpiry(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "keys.json"))
	key, _, err := s.Create("short", time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	v, _ := NewVerifier(s)
	if _, ok := v.Verify(key); ok {
		t.Fatal("expired key accepted")
	}
}
