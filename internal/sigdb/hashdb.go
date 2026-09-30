// Package sigdb implements FileGate's SHA-256 signature database.
//
// On-disk format (little endian):
//
//	magic   [8]byte  "FGHDB\x00\x00\x01"
//	created int64    unix seconds
//	nsrc    uint16   number of source names
//	nsrc x (uint16 len, name bytes)
//	count   uint64   number of records
//	count x record   (32-byte SHA-256, 1-byte source index), sorted by hash
//
// The record table is memory-mapped and binary searched, so loading is O(1)
// and lookups are O(log n) with no parsing at startup.
package sigdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/isaluki/filegate/internal/config"
)

var magic = [8]byte{'F', 'G', 'H', 'D', 'B', 0, 0, 1}

const recSize = 33

type Hash = [32]byte

// DB is an immutable, loaded hash database.
type DB struct {
	Created time.Time
	Sources []string
	records []byte // count*recSize, sorted
	unmap   func()
	path    string
	modTime time.Time
}

// Count returns the number of hashes in the database.
func (d *DB) Count() int {
	if d == nil {
		return 0
	}
	return len(d.records) / recSize
}

// Path returns the file the DB was loaded from.
func (d *DB) Path() string { return d.path }

// ModTime returns the modification time of the file when it was loaded.
func (d *DB) ModTime() time.Time { return d.modTime }

// Lookup returns the source name if h is a known-malicious hash.
func (d *DB) Lookup(h Hash) (string, bool) {
	if d == nil {
		return "", false
	}
	n := len(d.records) / recSize
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(d.records[i*recSize:i*recSize+32], h[:]) >= 0
	})
	if i < n && bytes.Equal(d.records[i*recSize:i*recSize+32], h[:]) {
		src := int(d.records[i*recSize+32])
		if src < len(d.Sources) {
			return d.Sources[src], true
		}
		return "unknown", true
	}
	return "", false
}

// Each calls fn for every record in the database.
func (d *DB) Each(fn func(h Hash, source string)) {
	if d == nil {
		return
	}
	for i := 0; i+recSize <= len(d.records); i += recSize {
		var h Hash
		copy(h[:], d.records[i:i+32])
		src := "unknown"
		if s := int(d.records[i+32]); s < len(d.Sources) {
			src = d.Sources[s]
		}
		fn(h, src)
	}
}

// Close releases the memory mapping, if any.
func (d *DB) Close() {
	if d != nil && d.unmap != nil {
		d.unmap()
		d.unmap = nil
	}
}

// Open loads a database file. A missing file returns (nil, os.ErrNotExist).
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
	} else {
		if data, err = io.ReadAll(f); err != nil {
			return nil, err
		}
	}

	db, err := parse(data)
	if err != nil {
		if unmap != nil {
			unmap()
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	db.unmap = unmap
	db.path = path
	db.modTime = fi.ModTime()
	return db, nil
}

func parse(data []byte) (*DB, error) {
	if !bytes.Equal(data[:8], magic[:]) {
		return nil, errors.New("bad magic (not a FileGate hash database)")
	}
	p := 8
	db := &DB{Created: time.Unix(int64(binary.LittleEndian.Uint64(data[p:])), 0)}
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
	if p+8 > len(data) {
		return nil, errors.New("truncated header")
	}
	count := binary.LittleEndian.Uint64(data[p:])
	p += 8
	if uint64(len(data)-p) != count*recSize {
		return nil, fmt.Errorf("record table size mismatch: header says %d records", count)
	}
	db.records = data[p:]
	return db, nil
}

// Builder accumulates hashes and writes a database.
type Builder struct {
	hashes  map[Hash]uint8
	sources []string
	srcIdx  map[string]uint8
}

func NewBuilder() *Builder {
	return &Builder{hashes: make(map[Hash]uint8, 1<<20), srcIdx: map[string]uint8{}}
}

func (b *Builder) source(name string) uint8 {
	if i, ok := b.srcIdx[name]; ok {
		return i
	}
	if len(b.sources) >= 255 {
		return 254
	}
	i := uint8(len(b.sources))
	b.sources = append(b.sources, name)
	b.srcIdx[name] = i
	return i
}

// Add inserts a hash attributed to source. Existing attributions are kept.
func (b *Builder) Add(h Hash, source string) {
	if _, ok := b.hashes[h]; ok {
		return
	}
	b.hashes[h] = b.source(source)
}

// Len returns the number of unique hashes collected.
func (b *Builder) Len() int { return len(b.hashes) }

// AddDB copies all records from an existing database.
func (b *Builder) AddDB(db *DB) { db.Each(b.Add) }

// ReadHashList parses a text list and adds every SHA-256 found. Lines may
// contain comments (#), CSV fields or quotes; the first 64-hex token is used.
func (b *Builder) ReadHashList(r io.Reader, source string) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		if h, ok := ParseHashLine(sc.Text()); ok {
			b.Add(h, source)
			n++
		}
	}
	return n, sc.Err()
}

// ParseHashLine extracts the first SHA-256 from a feed line.
func ParseHashLine(line string) (Hash, bool) {
	var h Hash
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return h, false
	}
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ';' || r == '|'
	}) {
		if len(tok) == 64 {
			if _, err := hex.Decode(h[:], []byte(tok)); err == nil {
				return h, true
			}
		}
	}
	return h, false
}

// Write serialises the builder to path atomically.
func (b *Builder) Write(path string) error {
	keys := make([]Hash, 0, len(b.hashes))
	for h := range b.hashes {
		keys = append(keys, h)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })

	var buf bytes.Buffer
	buf.Grow(64 + len(keys)*recSize)
	buf.Write(magic[:])
	_ = binary.Write(&buf, binary.LittleEndian, uint64(time.Now().Unix()))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(b.sources)))
	for _, s := range b.sources {
		if len(s) > 1024 {
			s = s[:1024]
		}
		_ = binary.Write(&buf, binary.LittleEndian, uint16(len(s)))
		buf.WriteString(s)
	}
	_ = binary.Write(&buf, binary.LittleEndian, uint64(len(keys)))
	for _, h := range keys {
		buf.Write(h[:])
		buf.WriteByte(b.hashes[h])
	}
	return config.WriteFileAtomic(path, buf.Bytes(), 0o644)
}
