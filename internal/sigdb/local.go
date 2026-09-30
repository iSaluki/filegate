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
}

// LoadLocalList reads every *.txt file in dir. A missing dir yields an empty list.
func LoadLocalList(dir string) (*LocalList, error) {
	l := &LocalList{entries: map[Hash]string{}}
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
		var h Hash
		if len(fields[0]) != 64 {
			continue
		}
		if _, err := hex.Decode(h[:], []byte(strings.ToLower(fields[0]))); err != nil {
			continue
		}
		name := base
		if len(fields) > 1 {
			name = strings.Join(fields[1:], " ")
		}
		l.entries[h] = name
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

// Len returns the number of entries.
func (l *LocalList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}
