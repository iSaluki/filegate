package sigdb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/isaluki/filegate/internal/config"
)

// nBuckets partitions records by their first byte so each bucket can be
// sorted independently in memory. Hashes are uniformly distributed, so 64
// buckets keep peak memory to ~1/64th of the table (about 10 MB for 35M MD5s).
const nBuckets = 64

type spill struct {
	hashLen int
	files   [nBuckets]*os.File
	w       [nBuckets]*bufio.Writer
	n       int64
}

func (s *spill) add(dir, prefix string, h []byte, src uint8) error {
	i := int(h[0]) * nBuckets / 256
	if s.w[i] == nil {
		f, err := os.CreateTemp(dir, prefix)
		if err != nil {
			return err
		}
		s.files[i], s.w[i] = f, bufio.NewWriterSize(f, 64*1024)
	}
	s.w[i].Write(h)
	s.n++
	return s.w[i].WriteByte(src)
}

// Builder accumulates hashes on disk and writes a sorted database. Memory
// use is bounded by the largest bucket, not the total number of hashes.
type Builder struct {
	dir     string
	sources []string
	srcIdx  map[string]uint8
	sha256  spill
	md5     spill
	err     error
}

// NewBuilder creates a builder spilling to a temp dir inside dir ("" = os.TempDir()).
func NewBuilder(dir string) (*Builder, error) {
	tmp, err := os.MkdirTemp(dir, ".fgbuild-")
	if err != nil {
		return nil, err
	}
	return &Builder{dir: tmp, srcIdx: map[string]uint8{}, sha256: spill{hashLen: 32}, md5: spill{hashLen: 16}}, nil
}

// ReserveSources registers source names in priority order: when the same
// hash comes from several sources, the earliest-registered source is kept.
func (b *Builder) ReserveSources(names ...string) {
	for _, n := range names {
		b.source(n)
	}
}

// Close removes temporary files.
func (b *Builder) Close() {
	for _, s := range []*spill{&b.sha256, &b.md5} {
		for _, f := range s.files {
			if f != nil {
				f.Close()
			}
		}
	}
	os.RemoveAll(b.dir)
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

func (b *Builder) setErr(err error) {
	if err != nil && b.err == nil {
		b.err = err
	}
}

// Hashes of the empty file; feeds occasionally list them (e.g. a malware
// URL served an empty response) and they would match every empty file.
var (
	emptySHA256 = Hash{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
	emptyMD5 = HashMD5{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}
)

// Add inserts a SHA-256. Duplicates are removed at Write time.
func (b *Builder) Add(h Hash, source string) {
	if h == emptySHA256 {
		return
	}
	b.setErr(b.sha256.add(b.dir, "s", h[:], b.source(source)))
}

// AddMD5 inserts an MD5.
func (b *Builder) AddMD5(h HashMD5, source string) {
	if h == emptyMD5 {
		return
	}
	b.setErr(b.md5.add(b.dir, "m", h[:], b.source(source)))
}

// Pending returns the number of hashes added so far (before de-duplication).
func (b *Builder) Pending() int64 { return b.sha256.n + b.md5.n }

// AddDB copies records from db whose source satisfies keep (nil = all).
func (b *Builder) AddDB(db *DB, keep func(source string) bool) {
	if db == nil {
		return
	}
	// Source indices are remapped lazily so only sources that actually
	// contribute records are registered.
	const unset, skip = -2, -1
	remap := make([]int, 256)
	for i := range remap {
		remap[i] = unset
	}
	copyTable := func(t table, s *spill, prefix string) {
		rs := t.recSize()
		for off := 0; off+rs <= len(t.recs); off += rs {
			src := t.recs[off+t.hashLen]
			if remap[src] == unset {
				remap[src] = skip
				if name := db.source(src); keep == nil || keep(name) {
					remap[src] = int(b.source(name))
				}
			}
			h := t.recs[off : off+t.hashLen]
			if bytes.Equal(h, emptySHA256[:]) || bytes.Equal(h, emptyMD5[:]) {
				continue // purge from databases built before this filter existed
			}
			if m := remap[src]; m >= 0 {
				b.setErr(s.add(b.dir, prefix, h, uint8(m)))
			}
		}
	}
	copyTable(db.sha256, &b.sha256, "s")
	copyTable(db.md5, &b.md5, "m")
}

// ReadHashList parses a feed and adds one hash per line. Lines may be plain
// lists, CSV or quoted; the first SHA-256 on a line is used, else the first
// MD5. Comment lines (#, ;) are skipped. It returns the number of hashes added.
func (b *Builder) ReadHashList(r io.Reader, source string) (int, error) {
	return ReadHashes(r, func(h256 *Hash, hmd5 *HashMD5) {
		if h256 != nil {
			b.Add(*h256, source)
		} else {
			b.AddMD5(*hmd5, source)
		}
	})
}

// ReadHashes streams hashes from a feed to fn (exactly one argument is non-nil).
func ReadHashes(r io.Reader, fn func(*Hash, *HashMD5)) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	n := 0
	for sc.Scan() {
		if h256, hmd5, ok := ParseHashLine(sc.Text()); ok {
			if h256 != nil {
				fn(h256, nil)
			} else {
				fn(nil, hmd5)
			}
			n++
		}
	}
	return n, sc.Err()
}

func isSep(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ';' || r == '|' || r == ':'
}

// ParseHashLine extracts the first SHA-256 (preferred) or MD5 from a line.
func ParseHashLine(line string) (*Hash, *HashMD5, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return nil, nil, false
	}
	var md5 *HashMD5
	for _, tok := range strings.FieldsFunc(line, isSep) {
		switch len(tok) {
		case 64:
			var h Hash
			if _, err := hex.Decode(h[:], []byte(tok)); err == nil {
				return &h, nil, true
			}
		case 32:
			if md5 == nil {
				var h HashMD5
				if _, err := hex.Decode(h[:], []byte(tok)); err == nil {
					md5 = &h
				}
			}
		}
	}
	return nil, md5, md5 != nil
}

// Counts reports the unique records written.
type Counts struct{ SHA256, MD5 int64 }

// Write sorts, de-duplicates and writes the database atomically to path.
func (b *Builder) Write(path string) (Counts, error) {
	var c Counts
	if b.err != nil {
		return c, b.err
	}
	out, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return c, err
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	defer out.Close()

	var hdr bytes.Buffer
	hdr.Write(magicV2[:])
	_ = binary.Write(&hdr, binary.LittleEndian, uint64(time.Now().Unix()))
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(len(b.sources)))
	for _, s := range b.sources {
		if len(s) > 1024 {
			s = s[:1024]
		}
		_ = binary.Write(&hdr, binary.LittleEndian, uint16(len(s)))
		hdr.WriteString(s)
	}
	countsAt := int64(hdr.Len())
	hdr.Write(make([]byte, 16)) // n256, nmd5 patched below
	if _, err := out.Write(hdr.Bytes()); err != nil {
		return c, err
	}
	w := bufio.NewWriterSize(out, 1<<20)
	if c.SHA256, err = b.sha256.writeSorted(w); err != nil {
		return c, err
	}
	if c.MD5, err = b.md5.writeSorted(w); err != nil {
		return c, err
	}
	if err := w.Flush(); err != nil {
		return c, err
	}
	var counts [16]byte
	binary.LittleEndian.PutUint64(counts[:8], uint64(c.SHA256))
	binary.LittleEndian.PutUint64(counts[8:], uint64(c.MD5))
	if _, err := out.WriteAt(counts[:], countsAt); err != nil {
		return c, err
	}
	if err := out.Sync(); err != nil {
		return c, err
	}
	if err := out.Close(); err != nil {
		return c, err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return c, err
	}
	config.MatchDirOwner(tmp)
	return c, os.Rename(tmp, path)
}

// recs sorts fixed-size records by (hash, source).
type recs struct {
	b    []byte
	size int
	tmp  []byte
}

func (r recs) Len() int { return len(r.b) / r.size }
func (r recs) Less(i, j int) bool {
	return bytes.Compare(r.b[i*r.size:(i+1)*r.size], r.b[j*r.size:(j+1)*r.size]) < 0
}
func (r recs) Swap(i, j int) {
	a, c := r.b[i*r.size:(i+1)*r.size], r.b[j*r.size:(j+1)*r.size]
	copy(r.tmp, a)
	copy(a, c)
	copy(c, r.tmp)
}

func (s *spill) writeSorted(w io.Writer) (int64, error) {
	rs := s.hashLen + 1
	var n int64
	for i := 0; i < nBuckets; i++ {
		if s.files[i] == nil {
			continue
		}
		if err := s.w[i].Flush(); err != nil {
			return n, err
		}
		if _, err := s.files[i].Seek(0, io.SeekStart); err != nil {
			return n, err
		}
		data, err := io.ReadAll(s.files[i])
		if err != nil {
			return n, err
		}
		if len(data)%rs != 0 {
			return n, errors.New("corrupt spill file")
		}
		sort.Sort(recs{b: data, size: rs, tmp: make([]byte, rs)})
		// Keep the first record per hash (lowest source index wins).
		var prev []byte
		for off := 0; off < len(data); off += rs {
			h := data[off : off+s.hashLen]
			if prev != nil && bytes.Equal(prev, h) {
				continue
			}
			if _, err := w.Write(data[off : off+rs]); err != nil {
				return n, err
			}
			prev = h
			n++
		}
	}
	return n, nil
}
