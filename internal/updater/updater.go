// Package updater keeps FileGate's signature database current by pulling
// hash feeds (MalwareBazaar, ThreatFox, URLhaus, VirusShare by default) and
// optionally running freshclam.
//
// The database is split into a large base file, rebuilt on full refreshes,
// and a small delta file that incremental updates rewrite. Each source's
// entries are tracked, so a full refresh replaces a feed's old entries with
// its new export while keeping entries from feeds that were not re-downloaded
// (incremental windows, append-only shards, or feeds that failed this time).
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
	NextShard    int       `json:"next_shard,omitempty"` // append feeds
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
	if b, err := os.ReadFile(scanner.UpdateStatePath(cfg)); err == nil {
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
	New         int    `json:"new,omitempty"`
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
	if _, err := os.Stat(scanner.DBPath(cfg)); err != nil {
		return true
	}
	return time.Since(LoadState(cfg).LastAttempt) >= cfg.UpdateInterval.Duration
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

type run struct {
	cfg    *config.Config
	st     State
	rep    *Report
	client *http.Client
	logf   func(string, ...any)
}

// Run performs an update.
func Run(ctx context.Context, cfg *config.Config, opt Options) (*Report, error) {
	start := time.Now()
	r := &run{cfg: cfg, client: &http.Client{Timeout: 30 * time.Minute}, logf: func(format string, a ...any) {
		if opt.Log != nil {
			fmt.Fprintf(opt.Log, format+"\n", a...)
		}
	}}
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

	r.st = LoadState(cfg)
	r.st.LastAttempt = time.Now()
	base := openOrNil(scanner.DBPath(cfg), r.logf)
	delta := openOrNil(scanner.DeltaPath(cfg), r.logf)
	if base == nil && delta != nil {
		delta.Close() // a delta is meaningless without its base
		delta = nil
	}
	if base == nil {
		// Rebuilding from scratch: append-only feeds must start over.
		for name, fs := range r.st.Feeds {
			fs.NextShard = 0
			r.st.Feeds[name] = fs
		}
	}
	r.rep = &Report{Before: base.Count() + delta.Count()}
	r.rep.Full = opt.Force || base == nil || time.Since(r.st.LastFull) >= cfg.FullRefreshInterval.Duration

	if r.rep.Full {
		err = r.full(ctx, base, delta)
	} else {
		err = r.incremental(ctx, base, delta)
	}
	base.Close()
	delta.Close()

	if set, oerr := sigdb.OpenSet(scanner.DBPath(cfg), scanner.DeltaPath(cfg)); oerr == nil {
		r.rep.After = set.Count()
		set.Close()
	}
	if err == nil {
		r.st.LastUpdate = time.Now()
		r.st.LastError = ""
	} else {
		r.st.LastError = err.Error()
	}
	if serr := saveState(cfg, r.st); serr != nil {
		r.logf("warning: saving update state: %v", serr)
	}
	if cfg.ClamAV.RunFreshclam {
		r.rep.Freshclam = runFreshclam(ctx, r.logf)
	}
	r.rep.DurationMS = time.Since(start).Milliseconds()
	return r.rep, err
}

func openOrNil(path string, logf func(string, ...any)) *sigdb.DB {
	db, err := sigdb.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logf("ignoring unreadable database %s: %v", path, err)
		}
		return nil
	}
	return db
}

// newBuilder creates a builder with sources registered in config order.
func (r *run) newBuilder() (*sigdb.Builder, error) {
	b, err := sigdb.NewBuilder(r.cfg.DataDir)
	if err != nil {
		return nil, err
	}
	for _, f := range r.cfg.Feeds {
		if f.Enabled {
			b.ReserveSources(f.Name)
		}
	}
	return b, nil
}

func (r *run) enabledSources() map[string]bool {
	m := map[string]bool{}
	for _, f := range r.cfg.Feeds {
		if f.Enabled {
			m[f.Name] = true
		}
	}
	return m
}

// full rebuilds the base from every non-append feed, carries over entries
// from sources that were not replaced, then adds any new append shards.
func (r *run) full(ctx context.Context, base, delta *sigdb.DB) error {
	b, err := r.newBuilder()
	if err != nil {
		return err
	}
	defer b.Close()
	replaced := map[string]bool{}
	fullOK, anyOK := true, false
	for _, feed := range r.cfg.Feeds {
		if !feed.Enabled || feed.Refresh == "append" {
			continue
		}
		fr := FeedReport{Name: feed.Name}
		fs := r.st.Feeds[feed.Name]
		r.logf("fetching %s (%s)", feed.Name, feed.URL)
		n, _, ns, err := r.fetch(ctx, feed, fs, false, func(h *sigdb.Hash, m *sigdb.HashMD5) {
			if h != nil {
				b.Add(*h, feed.Name)
			} else {
				b.AddMD5(*m, feed.Name)
			}
		})
		if err != nil {
			fr.Error, fs.LastError = err.Error(), err.Error()
			if feed.Refresh == "full" {
				fullOK = false
			}
			r.logf("  %s: error: %v", feed.Name, err)
		} else {
			anyOK = true
			fr.Hashes = n
			ns.LastSuccess, ns.Hashes, ns.NextShard = time.Now(), n, fs.NextShard
			fs = ns
			if feed.Refresh == "full" {
				replaced[feed.Name] = true
			}
			r.logf("  %s: %d hashes", feed.Name, n)
		}
		r.st.Feeds[feed.Name] = fs
		r.rep.Feeds = append(r.rep.Feeds, fr)
	}
	if !anyOK {
		return errors.New("all signature feeds failed")
	}
	enabled := r.enabledSources()
	keep := func(src string) bool { return enabled[src] && !replaced[src] }
	b.AddDB(base, keep)
	b.AddDB(delta, keep)
	r.logf("writing signature database (%d records before de-duplication)", b.Pending())
	c, err := b.Write(scanner.DBPath(r.cfg))
	if err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	r.rep.Changed = true
	_ = os.Remove(scanner.DeltaPath(r.cfg)) // folded into the base
	r.logf("database: %d SHA-256 + %d MD5 signatures", c.SHA256, c.MD5)
	if fullOK && anyOK {
		r.st.LastFull = time.Now()
	}
	// Persist progress before the (possibly long) append pass so scanners
	// can use the new base while shards download.
	r.st.LastUpdate = time.Now()
	_ = saveState(r.cfg, r.st)

	// Append-only sharded feeds: fetch new shards and fold them into the base.
	b2, err := r.newBuilder()
	if err != nil {
		return err
	}
	defer b2.Close()
	if !r.appendFeeds(ctx, b2, nil) {
		return nil
	}
	newBase, err := sigdb.Open(scanner.DBPath(r.cfg))
	if err != nil {
		return err
	}
	b2.AddDB(newBase, nil)
	newBase.Close()
	if c, err = b2.Write(scanner.DBPath(r.cfg)); err != nil {
		return fmt.Errorf("writing database: %w", err)
	}
	r.logf("database: %d SHA-256 + %d MD5 signatures", c.SHA256, c.MD5)
	return nil
}

// incremental fetches incremental and append feeds, keeping only hashes not
// already in the base, and rewrites the (small) delta file.
func (r *run) incremental(ctx context.Context, base, delta *sigdb.DB) error {
	b, err := r.newBuilder()
	if err != nil {
		return err
	}
	defer b.Close()
	isNew := func(h *sigdb.Hash, m *sigdb.HashMD5) bool {
		if h != nil {
			_, known := base.Lookup(*h)
			return !known
		}
		_, known := base.LookupMD5(*m)
		return !known
	}
	anyOK, attempted := false, false
	for _, feed := range r.cfg.Feeds {
		if !feed.Enabled || feed.Refresh == "append" {
			continue
		}
		fr := FeedReport{Name: feed.Name}
		if feed.Refresh == "full" {
			fr.Skipped = true
			r.rep.Feeds = append(r.rep.Feeds, fr)
			continue
		}
		attempted = true
		fs := r.st.Feeds[feed.Name]
		r.logf("fetching %s (%s)", feed.Name, feed.URL)
		n, notMod, ns, err := r.fetch(ctx, feed, fs, true, func(h *sigdb.Hash, m *sigdb.HashMD5) {
			if !isNew(h, m) {
				return
			}
			fr.New++
			if h != nil {
				b.Add(*h, feed.Name)
			} else {
				b.AddMD5(*m, feed.Name)
			}
		})
		if err != nil {
			fr.Error, fs.LastError = err.Error(), err.Error()
			r.logf("  %s: error: %v", feed.Name, err)
		} else {
			anyOK = true
			fr.Hashes, fr.NotModified = n, notMod
			ns.LastSuccess, ns.NextShard = time.Now(), fs.NextShard
			ns.Hashes = fs.Hashes
			if !notMod {
				ns.Hashes = n
			}
			fs = ns
			r.logf("  %s: %d hashes, %d new", feed.Name, n, fr.New)
		}
		r.st.Feeds[feed.Name] = fs
		r.rep.Feeds = append(r.rep.Feeds, fr)
	}
	appended := r.appendFeeds(ctx, b, isNew)
	for _, f := range r.rep.Feeds {
		if f.Error == "" && !f.Skipped {
			anyOK = true
		}
	}
	if attempted && !anyOK {
		return errors.New("all signature feeds failed")
	}
	if b.Pending() == 0 && !appended {
		return nil
	}
	b.AddDB(delta, func(src string) bool { return r.enabledSources()[src] })
	c, err := b.Write(scanner.DeltaPath(r.cfg))
	if err != nil {
		return fmt.Errorf("writing delta database: %w", err)
	}
	r.rep.Changed = true
	r.logf("delta database: %d SHA-256 + %d MD5 signatures", c.SHA256, c.MD5)
	return nil
}

// appendFeeds downloads shards not fetched yet. It reports whether any new
// hashes were added. filter (optional) drops hashes already known.
func (r *run) appendFeeds(ctx context.Context, b *sigdb.Builder, filter func(*sigdb.Hash, *sigdb.HashMD5) bool) bool {
	added := false
	for _, feed := range r.cfg.Feeds {
		if !feed.Enabled || feed.Refresh != "append" {
			continue
		}
		fs := r.st.Feeds[feed.Name]
		fr := FeedReport{Name: feed.Name}
		start := fs.NextShard
		r.logf("fetching %s from shard %d", feed.Name, start)
		for i := start; ctx.Err() == nil; i++ {
			shard := feed
			shard.URL = fmt.Sprintf(feed.URL, i)
			n, _, _, err := r.fetch(ctx, shard, feedState{}, false, func(h *sigdb.Hash, m *sigdb.HashMD5) {
				if filter != nil && !filter(h, m) {
					return
				}
				fr.New++
				if h != nil {
					b.Add(*h, feed.Name)
				} else {
					b.AddMD5(*m, feed.Name)
				}
			})
			var nf *notFoundError
			if errors.As(err, &nf) {
				break // no more shards published yet
			}
			if err != nil {
				fr.Error, fs.LastError = err.Error(), err.Error()
				r.logf("  %s shard %d: error: %v", feed.Name, i, err)
				break
			}
			fr.Hashes += n
			fs.NextShard = i + 1
			fs.Hashes += n
			if (i-start+1)%50 == 0 {
				r.logf("  %s: %d shards fetched", feed.Name, i-start+1)
			}
		}
		if fr.Error == "" {
			fs.LastSuccess, fs.LastError = time.Now(), ""
		}
		if fs.NextShard > start {
			r.logf("  %s: %d new shards, %d hashes", feed.Name, fs.NextShard-start, fr.Hashes)
		} else {
			fr.NotModified = fr.Error == ""
			r.logf("  %s: no new shards", feed.Name)
		}
		added = added || fr.New > 0
		r.st.Feeds[feed.Name] = fs
		r.rep.Feeds = append(r.rep.Feeds, fr)
	}
	return added
}

type notFoundError struct{ url string }

func (e *notFoundError) Error() string { return "not found: " + e.url }

// fetch downloads one feed and streams its hashes to fn.
func (r *run) fetch(ctx context.Context, feed config.Feed, fs feedState, conditional bool, fn func(*sigdb.Hash, *sigdb.HashMD5)) (int, bool, feedState, error) {
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
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, false, fs, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return 0, true, fs, nil
	case http.StatusNotFound:
		return 0, false, fs, &notFoundError{feed.URL}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, false, fs, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	ns := feedState{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}

	if feed.Format != "zip" {
		n, err := sigdb.ReadHashes(io.LimitReader(resp.Body, 8<<30), fn)
		return n, false, ns, err
	}
	tmp, err := os.CreateTemp(r.cfg.DataDir, ".feed-*.zip")
	if err != nil {
		return 0, false, fs, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	size, err := io.Copy(tmp, io.LimitReader(resp.Body, 4<<30))
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
		n, err := sigdb.ReadHashes(io.LimitReader(rc, 16<<30), fn)
		rc.Close()
		total += n
		if err != nil {
			return total, false, fs, err
		}
	}
	if total == 0 {
		return 0, false, fs, errors.New("feed contained no hashes")
	}
	return total, false, ns, nil
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
		logf("freshclam failed: %v %s", err, strings.TrimSpace(string(out)))
		return "error: " + err.Error()
	}
	logf("freshclam: ClamAV databases up to date")
	return "ok"
}
