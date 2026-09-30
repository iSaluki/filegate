package sigdb

import (
	"errors"
	"os"
	"time"
)

// Set is the scanner's view of the signature database: a large base file
// rebuilt on full refreshes plus a small delta file that incremental updates
// rewrite, so hourly updates never rewrite hundreds of megabytes.
type Set struct {
	Base, Delta *DB
}

// OpenSet loads base and delta. Missing files are not errors.
func OpenSet(basePath, deltaPath string) (*Set, error) {
	s := &Set{}
	var err error
	if s.Base, err = Open(basePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.Delta, err = Open(deltaPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.Base.Close()
		return nil, err
	}
	return s, nil
}

func (s *Set) dbs() []*DB {
	if s == nil {
		return nil
	}
	return []*DB{s.Base, s.Delta}
}

// Lookup checks a SHA-256 against both files.
func (s *Set) Lookup(h Hash) (string, bool) {
	for _, d := range s.dbs() {
		if src, ok := d.Lookup(h); ok {
			return src, true
		}
	}
	return "", false
}

// LookupMD5 checks an MD5 against both files.
func (s *Set) LookupMD5(h HashMD5) (string, bool) {
	for _, d := range s.dbs() {
		if src, ok := d.LookupMD5(h); ok {
			return src, true
		}
	}
	return "", false
}

// Count returns the total number of hashes (the files are disjoint).
func (s *Set) Count() int {
	n := 0
	for _, d := range s.dbs() {
		n += d.Count()
	}
	return n
}

// Created returns the newest build time.
func (s *Set) Created() time.Time {
	var t time.Time
	for _, d := range s.dbs() {
		if d != nil && d.Created.After(t) {
			t = d.Created
		}
	}
	return t
}

// Sources lists every source name present.
func (s *Set) Sources() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range s.dbs() {
		if d == nil {
			continue
		}
		for _, src := range d.Sources {
			if !seen[src] {
				seen[src] = true
				out = append(out, src)
			}
		}
	}
	return out
}

// ModTimes identifies the loaded file versions for change detection.
func (s *Set) ModTimes() [2]time.Time {
	var t [2]time.Time
	for i, d := range s.dbs() {
		if d != nil {
			t[i] = d.ModTime()
		}
	}
	return t
}

// Close unmaps both files.
func (s *Set) Close() {
	for _, d := range s.dbs() {
		d.Close()
	}
}
