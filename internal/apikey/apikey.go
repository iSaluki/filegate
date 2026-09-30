// Package apikey manages FileGate API keys. Only SHA-256 digests of keys are
// stored; the plaintext key is shown exactly once, when it is created.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/isaluki/filegate/internal/config"
)

const keyPrefix = "fg_"

// Key is a stored API key record.
type Key struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Hash    string    `json:"sha256"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitempty"`
}

// Expired reports whether the key has passed its expiry time.
func (k Key) Expired(now time.Time) bool { return !k.Expires.IsZero() && now.After(k.Expires) }

type file struct {
	Keys []Key `json:"keys"`
}

// Store is a keys.json file.
type Store struct {
	path string
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Path() string { return s.path }

// List returns all keys.
func (s *Store) List() ([]Key, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	return f.Keys, nil
}

func (s *Store) save(keys []Key) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(file{Keys: keys}, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(s.path, append(b, '\n'), 0o640)
}

func digest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// Create generates a new key. The returned plaintext must be shown to the
// user now; it cannot be recovered later.
func (s *Store) Create(name string, ttl time.Duration) (string, Key, error) {
	keys, err := s.List()
	if err != nil {
		return "", Key{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	for _, k := range keys {
		if k.Name == name {
			return "", Key{}, fmt.Errorf("a key named %q already exists", name)
		}
	}
	plain := keyPrefix + randToken(32)
	k := Key{ID: "k_" + randToken(5), Name: name, Hash: digest(plain), Created: time.Now().UTC().Truncate(time.Second)}
	if ttl > 0 {
		k.Expires = k.Created.Add(ttl)
	}
	keys = append(keys, k)
	if err := s.save(keys); err != nil {
		return "", Key{}, err
	}
	return plain, k, nil
}

// Revoke deletes the key with the given ID or name.
func (s *Store) Revoke(idOrName string) (Key, error) {
	keys, err := s.List()
	if err != nil {
		return Key{}, err
	}
	for i, k := range keys {
		if k.ID == idOrName || k.Name == idOrName {
			keys = append(keys[:i], keys[i+1:]...)
			return k, s.save(keys)
		}
	}
	return Key{}, fmt.Errorf("no key with id or name %q", idOrName)
}

// Verifier authenticates presented keys, reloading the store when the file
// changes so creations and revocations take effect without a restart.
type Verifier struct {
	store   *Store
	mu      sync.RWMutex
	keys    []Key
	modTime time.Time
	checked time.Time
}

func NewVerifier(store *Store) (*Verifier, error) {
	v := &Verifier{store: store}
	return v, v.reload(true)
}

func (v *Verifier) reload(force bool) error {
	v.mu.RLock()
	fresh := time.Since(v.checked) < 2*time.Second
	v.mu.RUnlock()
	if fresh && !force {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checked = time.Now()
	fi, err := os.Stat(v.store.path)
	if errors.Is(err, os.ErrNotExist) {
		v.keys, v.modTime = nil, time.Time{}
		return nil
	}
	if err != nil {
		return err
	}
	if !force && fi.ModTime().Equal(v.modTime) {
		return nil
	}
	keys, err := v.store.List()
	if err != nil {
		return err
	}
	v.keys, v.modTime = keys, fi.ModTime()
	return nil
}

// Count returns the number of loaded keys.
func (v *Verifier) Count() int {
	_ = v.reload(false)
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys)
}

// Verify returns the matching key record if presented is valid.
func (v *Verifier) Verify(presented string) (Key, bool) {
	if !strings.HasPrefix(presented, keyPrefix) || len(presented) > 256 {
		return Key{}, false
	}
	_ = v.reload(false)
	d, _ := hex.DecodeString(digest(presented))
	v.mu.RLock()
	defer v.mu.RUnlock()
	now := time.Now()
	var match Key
	found := false
	for _, k := range v.keys {
		kd, err := hex.DecodeString(k.Hash)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(d, kd) == 1 && !k.Expired(now) {
			match, found = k, true
		}
	}
	return match, found
}
