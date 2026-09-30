package sigdb

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// LocalList is a small, human-editable hash list (custom signatures or an
// allowlist). Each line: "<sha256> [optional name...]".
type LocalList struct {
	entries map[Hash]string
	md5     map[HashMD5]string
}

// LoadLocalList reads every *.txt file in dir. A missing dir yields an empty list.
func LoadLocalList(dir string) (*LocalList, error) {
	l := &LocalList{entries: map[Hash]string{}, md5: map[HashMD5]string{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return l, err
	}
	for _, fn := range files {
		if err := l.loadFile(fn); err != nil {
			return l, err
		}
	}
	return l, nil
}

func (l *LocalList) loadFile(fn string) error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	base := strings.TrimSuffix(filepath.Base(fn), ".txt")
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		name := base
		if len(fields) > 1 {
			name = strings.Join(fields[1:], " ")
		}
		switch len(fields[0]) {
		case 64:
			var h Hash
			if _, err := hex.Decode(h[:], []byte(fields[0])); err == nil {
				l.entries[h] = name
			}
		case 32:
			var h HashMD5
			if _, err := hex.Decode(h[:], []byte(fields[0])); err == nil {
				l.md5[h] = name
			}
		}
	}
	return sc.Err()
}

// Lookup returns the entry's name if present.
func (l *LocalList) Lookup(h Hash) (string, bool) {
	if l == nil {
		return "", false
	}
	n, ok := l.entries[h]
	return n, ok
}

// LookupMD5 returns the entry's name if present.
func (l *LocalList) LookupMD5(h HashMD5) (string, bool) {
	if l == nil {
		return "", false
	}
	n, ok := l.md5[h]
	return n, ok
}

// Len returns the number of entries.
func (l *LocalList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries) + len(l.md5)
}
