// Package sigdb implements FileGate's hash signature database.
//
// On-disk format v2 (little endian):
//
//	magic     [8]byte  "FGHDB\x00\x00\x02"
//	created   int64    unix seconds
//	nsrc      uint16   number of source names
//	nsrc x (uint16 len, name bytes)
//	n256      uint64   number of SHA-256 records
//	nmd5      uint64   number of MD5 records
//	n256 x (32-byte SHA-256, 1-byte source index), sorted by hash
//	nmd5 x (16-byte MD5,     1-byte source index), sorted by hash
//
// Version 1 files (SHA-256 table only) are still readable. Tables are
// memory-mapped and binary searched, so loading is O(1) regardless of size.
package sigdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
	"time"
)

var (
	magicV1 = [8]byte{'F', 'G', 'H', 'D', 'B', 0, 0, 1}
	magicV2 = [8]byte{'F', 'G', 'H', 'D', 'B', 0, 0, 2}
)

type (
	Hash    = [32]byte // SHA-256
	HashMD5 = [16]byte
)

// table is a sorted array of fixed-size (hash, source) records.
type table struct {
	hashLen int
	recs    []byte
}

func (t table) recSize() int { return t.hashLen + 1 }
func (t table) count() int   { return len(t.recs) / t.recSize() }

func (t table) lookup(h []byte) (uint8, bool) {
	rs := t.recSize()
	n := t.count()
	i := sort.Search(n, func(i int) bool { return bytes.Compare(t.recs[i*rs:i*rs+t.hashLen], h) >= 0 })
	if i < n && bytes.Equal(t.recs[i*rs:i*rs+t.hashLen], h) {
		return t.recs[i*rs+t.hashLen], true
	}
	return 0, false
}

// DB is an immutable, loaded hash database.
type DB struct {
	Created time.Time
	Sources []string
	sha256  table
	md5     table
	unmap   func()
	path    string
	modTime time.Time
}

// Count returns the total number of hashes.
func (d *DB) Count() int {
	if d == nil {
		return 0
	}
	return d.sha256.count() + d.md5.count()
}

// CountSHA256 and CountMD5 return per-table sizes.
func (d *DB) CountSHA256() int {
	if d == nil {
		return 0
	}
	return d.sha256.count()
}

func (d *DB) CountMD5() int {
	if d == nil {
		return 0
	}
	return d.md5.count()
}

func (d *DB) Path() string       { return d.path }
func (d *DB) ModTime() time.Time { return d.modTime }

func (d *DB) source(i uint8) string {
	if int(i) < len(d.Sources) {
		return d.Sources[i]
	}
	return "unknown"
}

// Lookup returns the source name if h is a known-malicious SHA-256.
func (d *DB) Lookup(h Hash) (string, bool) {
	if d == nil {
		return "", false
	}
	s, ok := d.sha256.lookup(h[:])
	return d.source(s), ok
}

// LookupMD5 returns the source name if h is a known-malicious MD5.
func (d *DB) LookupMD5(h HashMD5) (string, bool) {
	if d == nil {
		return "", false
	}
	s, ok := d.md5.lookup(h[:])
	return d.source(s), ok
}

// Close releases the memory mapping, if any.
func (d *DB) Close() {
	if d != nil && d.unmap != nil {
		d.unmap()
		d.unmap = nil
	}
}

// Open loads a database file. A missing file returns an os.ErrNotExist error.
func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := fi.Size()
	if size < 8+8+2+8 {
		return nil, fmt.Errorf("%s: file too small to be a hash database", path)
	}
	var data []byte
	var unmap func()
	if m, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED); err == nil {
		data = m
		unmap = func() { _ = syscall.Munmap(m) }
	} else if data, err = io.ReadAll(f); err != nil {
		return nil, err
	}
	db, err := parse(data)
	if err != nil {
		if unmap != nil {
			unmap()
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	db.unmap, db.path, db.modTime = unmap, path, fi.ModTime()
	return db, nil
}

func parse(data []byte) (*DB, error) {
	v2 := bytes.Equal(data[:8], magicV2[:])
	if !v2 && !bytes.Equal(data[:8], magicV1[:]) {
		return nil, errors.New("bad magic (not a FileGate hash database)")
	}
	p := 8
	db := &DB{Created: time.Unix(int64(binary.LittleEndian.Uint64(data[p:])), 0),
		sha256: table{hashLen: 32}, md5: table{hashLen: 16}}
	p += 8
	nsrc := int(binary.LittleEndian.Uint16(data[p:]))
	p += 2
	for i := 0; i < nsrc; i++ {
		if p+2 > len(data) {
			return nil, errors.New("truncated source table")
		}
		l := int(binary.LittleEndian.Uint16(data[p:]))
		p += 2
		if p+l > len(data) {
			return nil, errors.New("truncated source table")
		}
		db.Sources = append(db.Sources, string(data[p:p+l]))
		p += l
	}
	var n256, nmd5 uint64
	if p+8 > len(data) {
		return nil, errors.New("truncated header")
	}
	n256 = binary.LittleEndian.Uint64(data[p:])
	p += 8
	if v2 {
		if p+8 > len(data) {
			return nil, errors.New("truncated header")
		}
		nmd5 = binary.LittleEndian.Uint64(data[p:])
		p += 8
	}
	need := n256*33 + nmd5*17
	if uint64(len(data)-p) != need {
		return nil, fmt.Errorf("record table size mismatch (header: %d SHA-256, %d MD5)", n256, nmd5)
	}
	db.sha256.recs = data[p : p+int(n256*33)]
	db.md5.recs = data[p+int(n256*33):]
	return db, nil
}
