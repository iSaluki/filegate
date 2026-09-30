package sigdb

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newBuilder(t *testing.T) *Builder {
	t.Helper()
	b, err := NewBuilder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestBuildOpenLookup(t *testing.T) {
	b := newBuilder(t)
	list := "# MalwareBazaar export\n" +
		"\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n" +
		"2024-01-01, 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 ,exe\n" +
		"not a hash\n\n"
	n, err := b.ReadHashList(strings.NewReader(list), "feedA")
	if err != nil || n != 2 {
		t.Fatalf("ReadHashList = %d, %v", n, err)
	}
	// URLhaus-style CSV line with both MD5 and SHA-256: the SHA-256 wins.
	urlhaus := `"2026-09-30","http://x/i586","elf","12d8982f4082705548942ab983c2085d","174dbc02039af436613f492a86073791d364334bc645ffbbc4236e9a62d32032","None"` + "\n"
	// VirusShare-style MD5 list.
	vs := "#####\n# VirusShare\n2d75cc1bf8e57872781f9cd04a529256\n00f538c3d410822e241486ca061a57ee\n"
	b.ReadHashList(strings.NewReader(urlhaus), "urlhaus")
	b.ReadHashList(strings.NewReader(vs), "virusshare")
	extra := sha256.Sum256([]byte("x"))
	b.Add(extra, "feedB")
	b.Add(extra, "feedC") // duplicate keeps the first source

	path := filepath.Join(t.TempDir(), "h.fgdb")
	c, err := b.Write(path)
	if err != nil {
		t.Fatal(err)
	}
	// The empty-file hash in the list is deliberately excluded.
	if c.SHA256 != 3 || c.MD5 != 2 {
		t.Fatalf("counts = %+v", c)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Count() != 5 || db.CountMD5() != 2 {
		t.Fatalf("count = %d md5 = %d", db.Count(), db.CountMD5())
	}
	if _, ok := db.Lookup(sha256.Sum256(nil)); ok {
		t.Fatal("empty-file hash must never be stored")
	}
	if src, ok := db.Lookup(extra); !ok || src != "feedB" {
		t.Fatalf("lookup extra = %q %v", src, ok)
	}
	h, _, _ := ParseHashLine("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8")
	if src, ok := db.Lookup(*h); !ok || src != "feedA" {
		t.Fatalf("lookup uppercase = %q %v", src, ok)
	}
	_, m, _ := ParseHashLine("2d75cc1bf8e57872781f9cd04a529256")
	if src, ok := db.LookupMD5(*m); !ok || src != "virusshare" {
		t.Fatalf("md5 lookup = %q %v", src, ok)
	}
	_, um, _ := ParseHashLine("12d8982f4082705548942ab983c2085d")
	if _, ok := db.LookupMD5(*um); ok {
		t.Fatal("URLhaus MD5 should not be stored when the line has a SHA-256")
	}
	if _, ok := db.Lookup(sha256.Sum256([]byte("y"))); ok {
		t.Fatal("unexpected hit")
	}

	// Rebuild from the DB, filtering one source.
	b2 := newBuilder(t)
	b2.AddDB(db, func(src string) bool { return src != "virusshare" })
	c2, err := b2.Write(filepath.Join(t.TempDir(), "h2.fgdb"))
	if err != nil || c2.SHA256 != 3 || c2.MD5 != 0 {
		t.Fatalf("filtered rebuild = %+v %v", c2, err)
	}
}

func TestManyHashesAcrossBuckets(t *testing.T) {
	b := newBuilder(t)
	const n = 50000
	for i := 0; i < n; i++ {
		b.Add(sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)}), "s")
		b.AddMD5(md5.Sum([]byte{byte(i), byte(i >> 8), byte(i >> 16)}), "m")
		if i%10 == 0 { // duplicates
			b.AddMD5(md5.Sum([]byte{byte(i), byte(i >> 8), byte(i >> 16)}), "m")
		}
	}
	path := filepath.Join(t.TempDir(), "big.fgdb")
	c, err := b.Write(path)
	if err != nil || c.SHA256 != n || c.MD5 != n {
		t.Fatalf("counts = %+v %v", c, err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < n; i += 997 {
		k := []byte{byte(i), byte(i >> 8), byte(i >> 16)}
		if _, ok := db.Lookup(sha256.Sum256(k)); !ok {
			t.Fatalf("sha256 %d missing", i)
		}
		if _, ok := db.LookupMD5(md5.Sum(k)); !ok {
			t.Fatalf("md5 %d missing", i)
		}
	}
}

func TestReadsV1Format(t *testing.T) {
	h := sha256.Sum256([]byte("legacy"))
	var buf []byte
	buf = append(buf, magicV1[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, 1700000000)
	buf = binary.LittleEndian.AppendUint16(buf, 1)
	buf = binary.LittleEndian.AppendUint16(buf, 3)
	buf = append(buf, "old"...)
	buf = binary.LittleEndian.AppendUint64(buf, 1)
	buf = append(buf, h[:]...)
	buf = append(buf, 0)
	path := filepath.Join(t.TempDir(), "v1.fgdb")
	os.WriteFile(path, buf, 0o644)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if src, ok := db.Lookup(h); !ok || src != "old" {
		t.Fatalf("v1 lookup = %q %v", src, ok)
	}
}

func TestSet(t *testing.T) {
	dir := t.TempDir()
	b := newBuilder(t)
	b.Add(sha256.Sum256([]byte("base")), "full")
	b.Write(filepath.Join(dir, "base"))
	d := newBuilder(t)
	d.AddMD5(md5.Sum([]byte("delta")), "recent")
	d.Write(filepath.Join(dir, "delta"))
	s, err := OpenSet(filepath.Join(dir, "base"), filepath.Join(dir, "delta"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 2 {
		t.Fatalf("count = %d", s.Count())
	}
	if _, ok := s.Lookup(sha256.Sum256([]byte("base"))); !ok {
		t.Fatal("base hash missing")
	}
	if src, ok := s.LookupMD5(md5.Sum([]byte("delta"))); !ok || src != "recent" {
		t.Fatal("delta hash missing")
	}
	// Missing files are fine.
	empty, err := OpenSet(filepath.Join(dir, "nope"), filepath.Join(dir, "nope2"))
	if err != nil || empty.Count() != 0 {
		t.Fatalf("empty set = %v %v", empty.Count(), err)
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
