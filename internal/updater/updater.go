// Package updater keeps FileGate's signature database current by pulling
// hash feeds (MalwareBazaar by default) and optionally running freshclam.
package updater

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
)

// UserAgent is sent with feed requests.
var UserAgent = "FileGate/dev (+https://github.com/isaluki/filegate)"

// ErrLocked is returned when another update is already running.
var ErrLocked = errors.New("another update is already in progress")

type feedState struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	Hashes       int       `json:"hashes"`
}

// State is persisted between updates.
type State struct {
	LastFull    time.Time            `json:"last_full"`
	LastUpdate  time.Time            `json:"last_update"`
	LastAttempt time.Time            `json:"last_attempt"`
	LastError   string               `json:"last_error,omitempty"`
	Feeds       map[string]feedState `json:"feeds"`
}

// LoadState reads the update state (zero value if absent).
func LoadState(cfg *config.Config) State {
	st := State{Feeds: map[string]feedState{}}
	b, err := os.ReadFile(scanner.UpdateStatePath(cfg))
	if err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Feeds == nil {
		st.Feeds = map[string]feedState{}
	}
	return st
}

func saveState(cfg *config.Config, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(scanner.UpdateStatePath(cfg), b, 0o644)
}

// FeedReport summarises one feed's download.
type FeedReport struct {
	Name        string `json:"name"`
	Hashes      int    `json:"hashes"`
	NotModified bool   `json:"not_modified,omitempty"`
	Skipped     bool   `json:"skipped,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Report summarises an update run.
type Report struct {
	Full       bool         `json:"full"`
	Feeds      []FeedReport `json:"feeds"`
	Before     int          `json:"hashes_before"`
	After      int          `json:"hashes_after"`
	Freshclam  string       `json:"freshclam,omitempty"`
	DurationMS int64        `json:"duration_ms"`
	Changed    bool         `json:"changed"`
}

// Options control an update run.
type Options struct {
	Force bool      // force a full rebuild
	Log   io.Writer // progress output (may be nil)
}

// Due reports whether an incremental update is due per the config.
func Due(cfg *config.Config) bool {
	st := LoadState(cfg)
	if _, err := os.Stat(scanner.DBPath(cfg)); err != nil {
		return true
	}
	return time.Since(st.LastAttempt) >= cfg.UpdateInterval.Duration
}

func lock(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".update.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// Run performs an update.
func Run(ctx context.Context, cfg *config.Config, opt Options) (*Report, error) {
	start := time.Now()
	logf := func(format string, a ...any) {
		if opt.Log != nil {
			fmt.Fprintf(opt.Log, format+"\n", a...)
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	for _, d := range []string{scanner.CustomSigDir(cfg), scanner.AllowlistDir(cfg)} {
		_ = os.MkdirAll(d, 0o755)
	}
	unlock, err := lock(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	st := LoadState(cfg)
	st.LastAttempt = time.Now()
	dbPath := scanner.DBPath(cfg)
	old, err := sigdb.Open(dbPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("existing database unreadable (%v); rebuilding", err)
		old = nil
	}
	defer old.Close()

	rep := &Report{Before: old.Count()}
	rep.Full = opt.Force || old == nil || time.Since(st.LastFull) >= cfg.FullRefreshInterval.Duration

	b := sigdb.NewBuilder()
	fullOK, fullTried := true, false
	anyOK := false
	client := &http.Client{Timeout: 15 * time.Minute}

	for _, feed := range cfg.Feeds {
		if !feed.Enabled {
			continue
		}
		fr := FeedReport{Name: feed.Name}
		if feed.Refresh == "full" && !rep.Full {
			fr.Skipped = true
			rep.Feeds = append(rep.Feeds, fr)
			continue
		}
		if feed.Refresh == "full" {
			fullTried = true
		}
		fs := st.Feeds[feed.Name]
		conditional := !rep.Full // full rebuilds need every feed's content
		logf("fetching %s (%s)", feed.Name, feed.URL)
		n, notMod, newState, err := fetchFeed(ctx, client, feed, fs, conditional, cfg.DataDir, b)
		if err != nil {
			fr.Error = err.Error()
			fs.LastError = err.Error()
			if feed.Refresh == "full" {
				fullOK = false
			}
			logf("  %s: error: %v", feed.Name, err)
		} else {
			anyOK = true
			fr.Hashes, fr.NotModified = n, notMod
			newState.LastSuccess = time.Now()
			newState.LastError = ""
			if !notMod {
				newState.Hashes = n
			} else {
				newState.Hashes = fs.Hashes
			}
			fs = newState
			if notMod {
				logf("  %s: not modified", feed.Name)
			} else {
				logf("  %s: %d hashes", feed.Name, n)
			}
		}
		st.Feeds[feed.Name] = fs
		rep.Feeds = append(rep.Feeds, fr)
	}

	// Keep previously known hashes unless a full rebuild fully succeeded.
	if old != nil && (!rep.Full || !fullTried || !fullOK) {
		b.AddDB(old)
	}

	var runErr error
	switch {
	case !anyOK && len(rep.Feeds) > 0 && countActive(rep.Feeds) > 0:
		runErr = errors.New("all signature feeds failed")
	case b.Len() == 0 && old == nil:
		logf("no hashes collected; database not written")
	default:
		if b.Len() != old.Count() || rep.Full || anyNew(rep.Feeds) {
			if err := b.Write(dbPath); err != nil {
				return rep, fmt.Errorf("writing database: %w", err)
			}
			rep.Changed = true
		}
	}
	rep.After = b.Len()
	if rep.After == 0 && old != nil {
		rep.After = old.Count()
	}

	if runErr == nil {
		st.LastUpdate = time.Now()
		st.LastError = ""
		if rep.Full && fullOK && fullTried {
			st.LastFull = time.Now()
		}
	} else {
		st.LastError = runErr.Error()
	}
	if err := saveState(cfg, st); err != nil {
		logf("warning: saving update state: %v", err)
	}

	if cfg.ClamAV.RunFreshclam {
		rep.Freshclam = runFreshclam(ctx, logf)
	}
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep, runErr
}

func countActive(fs []FeedReport) int {
	n := 0
	for _, f := range fs {
		if !f.Skipped {
			n++
		}
	}
	return n
}

func anyNew(fs []FeedReport) bool {
	for _, f := range fs {
		if !f.Skipped && !f.NotModified && f.Error == "" && f.Hashes > 0 {
			return true
		}
	}
	return false
}

func fetchFeed(ctx context.Context, client *http.Client, feed config.Feed, fs feedState, conditional bool, tmpDir string, b *sigdb.Builder) (int, bool, feedState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return 0, false, fs, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if feed.HeaderName != "" {
		req.Header.Set(feed.HeaderName, os.ExpandEnv(feed.HeaderValue))
	}
	if conditional {
		if fs.ETag != "" {
			req.Header.Set("If-None-Match", fs.ETag)
		}
		if fs.LastModified != "" {
			req.Header.Set("If-Modified-Since", fs.LastModified)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, fs, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return 0, true, fs, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, false, fs, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	ns := feedState{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}

	switch feed.Format {
	case "zip":
		tmp, err := os.CreateTemp(tmpDir, ".feed-*.zip")
		if err != nil {
			return 0, false, fs, err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		size, err := io.Copy(tmp, io.LimitReader(resp.Body, 2<<30))
		if err != nil {
			return 0, false, fs, err
		}
		zr, err := zip.NewReader(tmp, size)
		if err != nil {
			return 0, false, fs, fmt.Errorf("feed is not a valid zip: %w", err)
		}
		total := 0
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return total, false, fs, err
			}
			n, err := b.ReadHashList(io.LimitReader(rc, 4<<30), feed.Name)
			rc.Close()
			total += n
			if err != nil {
				return total, false, fs, err
			}
		}
		if total == 0 {
			return 0, false, fs, errors.New("feed contained no SHA-256 hashes")
		}
		return total, false, ns, nil
	default:
		n, err := b.ReadHashList(io.LimitReader(resp.Body, 2<<30), feed.Name)
		if err != nil {
			return n, false, fs, err
		}
		return n, false, ns, nil
	}
}

func runFreshclam(ctx context.Context, logf func(string, ...any)) string {
	bin, err := exec.LookPath("freshclam")
	if err != nil {
		logf("freshclam not installed; skipping ClamAV database update")
		return "not installed"
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--quiet", "--stdout").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		logf("freshclam failed: %v %s", err, msg)
		return "error: " + err.Error()
	}
	logf("freshclam: ClamAV databases up to date")
	return "ok"
}
