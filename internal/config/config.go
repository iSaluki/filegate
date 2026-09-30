// Package config loads and saves FileGate's configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	SystemConfigDir = "/etc/filegate"
	SystemDataDir   = "/var/lib/filegate"
	ConfigFileName  = "config.json"
	KeysFileName    = "keys.json"
)

// Duration is a time.Duration that marshals to/from strings like "1h30m".
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration must be a string like \"1h\": %w", err)
		}
		d.Duration = time.Duration(n) * time.Second
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Feed describes a downloadable list of malicious SHA-256 hashes.
type Feed struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Format  string `json:"format"`  // "text" (one hash per line) or "zip" (zip containing text files)
	Refresh string `json:"refresh"` // "full" (only on full rebuilds) or "incremental" (every update)
	// Optional HTTP header to send (e.g. abuse.ch "Auth-Key").
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type ClamAV struct {
	// Enabled: "auto" (use clamd if a socket is found), "on", or "off".
	Enabled string `json:"enabled"`
	// Socket is a unix socket path or tcp address (tcp://host:port). Empty = auto-detect.
	Socket  string   `json:"socket"`
	Timeout Duration `json:"timeout"`
	// RunFreshclam runs `freshclam` during `filegate update` (requires permission to the ClamAV DB).
	RunFreshclam bool `json:"run_freshclam"`
}

type Limits struct {
	MaxFileSize      int64 `json:"max_file_size"`      // largest single object analysed in memory
	MaxTotalExtract  int64 `json:"max_total_extract"`  // total bytes decompressed per scan
	MaxArchiveDepth  int   `json:"max_archive_depth"`  // nested archive depth
	MaxArchiveFiles  int   `json:"max_archive_files"`  // objects per scan
	MaxCompressRatio int   `json:"max_compress_ratio"` // ratio above which oversized entries are bombs
}

type Heuristics struct {
	Enabled bool `json:"enabled"`
	// Threshold is the per-object score at or above which the verdict is malicious.
	Threshold int `json:"threshold"`
	// BlockEncryptedExecutables flags password-protected archives containing executables/scripts.
	BlockEncryptedExecutables bool `json:"block_encrypted_executables"`
}

type API struct {
	Listen            string   `json:"listen"`
	MaxUploadSize     int64    `json:"max_upload_size"`
	MaxConcurrent     int      `json:"max_concurrent_scans"`
	TLSCert           string   `json:"tls_cert,omitempty"`
	TLSKey            string   `json:"tls_key,omitempty"`
	AutoUpdate        bool     `json:"auto_update"`
	DBReloadInterval  Duration `json:"db_reload_interval"`
	TrustProxyHeaders bool     `json:"trust_proxy_headers"`
}

type Config struct {
	DataDir             string     `json:"data_dir"`
	UpdateInterval      Duration   `json:"update_interval"`
	FullRefreshInterval Duration   `json:"full_refresh_interval"`
	Feeds               []Feed     `json:"feeds"`
	ClamAV              ClamAV     `json:"clamav"`
	Limits              Limits     `json:"limits"`
	Heuristics          Heuristics `json:"heuristics"`
	API                 API        `json:"api"`

	path string // where the config was loaded from
}

// Default returns a configuration with sane defaults using the given data dir.
func Default(dataDir string) *Config {
	return &Config{
		DataDir:             dataDir,
		UpdateInterval:      Duration{time.Hour},
		FullRefreshInterval: Duration{7 * 24 * time.Hour},
		Feeds: []Feed{
			{
				Name:    "malwarebazaar-full",
				URL:     "https://bazaar.abuse.ch/export/txt/sha256/full/",
				Format:  "zip",
				Refresh: "full",
				Enabled: true,
			},
			{
				Name:    "malwarebazaar-recent",
				URL:     "https://bazaar.abuse.ch/export/txt/sha256/recent/",
				Format:  "text",
				Refresh: "incremental",
				Enabled: true,
			},
		},
		ClamAV: ClamAV{Enabled: "auto", Timeout: Duration{60 * time.Second}},
		Limits: Limits{
			MaxFileSize:      256 << 20,
			MaxTotalExtract:  1 << 30,
			MaxArchiveDepth:  6,
			MaxArchiveFiles:  20000,
			MaxCompressRatio: 100,
		},
		Heuristics: Heuristics{Enabled: true, Threshold: 100, BlockEncryptedExecutables: true},
		API: API{
			Listen:           "127.0.0.1:8750",
			MaxUploadSize:    256 << 20,
			MaxConcurrent:    8,
			DBReloadInterval: Duration{time.Minute},
		},
	}
}

// ResolvePath picks which config file to use: explicit > $FILEGATE_CONFIG >
// system config (if present or running as root) > per-user config.
func ResolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("FILEGATE_CONFIG"); env != "" {
		return env
	}
	sys := filepath.Join(SystemConfigDir, ConfigFileName)
	if _, err := os.Stat(sys); !errors.Is(err, os.ErrNotExist) || os.Geteuid() == 0 {
		return sys
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "filegate", ConfigFileName)
	}
	return sys
}

func defaultDataDirFor(cfgPath string) string {
	if filepath.Dir(cfgPath) == SystemConfigDir || os.Geteuid() == 0 {
		return SystemDataDir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "filegate")
	}
	return SystemDataDir
}

// Load reads the config at path (resolved via ResolvePath). A missing file
// yields defaults; values present in the file override the defaults.
func Load(explicit string) (*Config, error) {
	path := ResolvePath(explicit)
	cfg := Default(defaultDataDirFor(path))
	cfg.path = path
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.path = path
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir must be set")
	}
	if c.Heuristics.Threshold <= 0 {
		c.Heuristics.Threshold = 100
	}
	if c.API.MaxConcurrent <= 0 {
		c.API.MaxConcurrent = 8
	}
	if c.Limits.MaxArchiveDepth <= 0 {
		c.Limits.MaxArchiveDepth = 6
	}
	if c.Limits.MaxCompressRatio <= 0 {
		c.Limits.MaxCompressRatio = 100
	}
	for _, f := range c.Feeds {
		if f.Format != "text" && f.Format != "zip" {
			return fmt.Errorf("feed %q: format must be \"text\" or \"zip\"", f.Name)
		}
		if f.Refresh != "full" && f.Refresh != "incremental" {
			return fmt.Errorf("feed %q: refresh must be \"full\" or \"incremental\"", f.Name)
		}
	}
	return nil
}

// Path is the file this config was loaded from (or would be saved to).
func (c *Config) Path() string { return c.path }

// SetPath overrides where Save writes to.
func (c *Config) SetPath(p string) { c.path = p }

// KeysPath is the API key store, kept next to the config file.
func (c *Config) KeysPath() string { return filepath.Join(filepath.Dir(c.path), KeysFileName) }

// Save writes the config atomically.
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(c.path, append(b, '\n'), 0o644)
}

// WriteFileAtomic writes data to a temp file in the same dir and renames it.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	MatchDirOwner(tmp)
	return os.Rename(tmp, path)
}
