package sigdb

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildOpenLookup(t *testing.T) {
	b := NewBuilder()
	list := "# MalwareBazaar export\n" +
		"\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n" +
		"2024-01-01, 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 ,exe\n" +
		"not a hash\n\n"
	n, err := b.ReadHashList(strings.NewReader(list), "feedA")
	if err != nil || n != 2 {
		t.Fatalf("ReadHashList = %d, %v", n, err)
	}
	extra := sha256.Sum256([]byte("x"))
	b.Add(extra, "feedB")
	b.Add(extra, "feedC") // duplicate keeps first source

	path := filepath.Join(t.TempDir(), "h.fgdb")
	if err := b.Write(path); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Count() != 3 {
		t.Fatalf("count = %d", db.Count())
	}
	if src, ok := db.Lookup(extra); !ok || src != "feedB" {
		t.Fatalf("lookup extra = %q %v", src, ok)
	}
	h, _ := ParseHashLine("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8")
	if src, ok := db.Lookup(h); !ok || src != "feedA" {
		t.Fatalf("lookup uppercase = %q %v", src, ok)
	}
	if _, ok := db.Lookup(sha256.Sum256([]byte("y"))); ok {
		t.Fatal("unexpected hit")
	}

	// Rebuild from the DB round-trips all records.
	b2 := NewBuilder()
	b2.AddDB(db)
	if b2.Len() != 3 {
		t.Fatalf("AddDB len = %d", b2.Len())
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(path, []byte(strings.Repeat("garbage!", 8)), 0o644)
	if _, err := Open(path); err == nil {
		t.Fatal("expected error for garbage file")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
