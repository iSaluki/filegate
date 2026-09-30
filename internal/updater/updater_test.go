package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
)

func h(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func m(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// feedServer serves mutable feed contents for tests.
type feedServer struct {
	mu     sync.Mutex
	full   []string // zipped
	recent []string
	shards [][]string
	fail   bool
}

func (f *feedServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/full", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail {
			http.Error(w, "down", 503)
			return
		}
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		fw, _ := zw.Create("full.csv")
		fmt.Fprintf(fw, "# header\n%s\n", strings.Join(f.full, "\n"))
		zw.Close()
		w.Write(b.Bytes())
	})
	mux.HandleFunc("/recent", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body := strings.Join(f.recent, "\n") + "\n"
		etag := `"` + h(body)[:8] + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		fmt.Fprint(w, body)
	})
	mux.HandleFunc("/shard/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var i int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/shard/"), "%05d.md5", &i)
		if i >= len(f.shards) {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "#####\n%s\n", strings.Join(f.shards[i], "\n"))
	})
	return mux
}

func setup(t *testing.T) (*config.Config, *feedServer) {
	t.Helper()
	fs := &feedServer{
		full:   []string{h("a"), h("b")},
		recent: []string{h("r1")},
		shards: [][]string{{m("v1"), m("v2")}},
	}
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := config.Default(t.TempDir())
	cfg.Feeds = []config.Feed{
		{Name: "full", URL: ts.URL + "/full", Format: "zip", Refresh: "full", Enabled: true},
		{Name: "recent", URL: ts.URL + "/recent", Format: "text", Refresh: "incremental", Enabled: true},
		{Name: "vs", URL: ts.URL + "/shard/%05d.md5", Format: "text", Refresh: "append", Enabled: true},
	}
	return cfg, fs
}

func lookup(t *testing.T, cfg *config.Config) *sigdb.Set {
	t.Helper()
	s, err := sigdb.OpenSet(scanner.DBPath(cfg), scanner.DeltaPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func has(s *sigdb.Set, hexHash string) bool {
	raw, _ := hex.DecodeString(hexHash)
	if len(raw) == 32 {
		var x sigdb.Hash
		copy(x[:], raw)
		_, ok := s.Lookup(x)
		return ok
	}
	var x sigdb.HashMD5
	copy(x[:], raw)
	_, ok := s.LookupMD5(x)
	return ok
}

func TestUpdateLifecycle(t *testing.T) {
	cfg, fs := setup(t)
	ctx := context.Background()

	// 1. First run: full rebuild including append shards.
	rep, err := Run(ctx, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Full || rep.After != 5 {
		t.Fatalf("first run: %+v", rep)
	}
	if st := LoadState(cfg); st.Feeds["vs"].NextShard != 1 {
		t.Fatalf("next shard = %d", st.Feeds["vs"].NextShard)
	}

	// 2. Incremental, nothing new: nothing rewritten.
	rep, err = Run(ctx, cfg, Options{})
	if err != nil || rep.Full || rep.Changed {
		t.Fatalf("idle incremental: %+v %v", rep, err)
	}
	if _, err := os.Stat(scanner.DeltaPath(cfg)); err == nil {
		t.Fatal("delta written without new hashes")
	}

	// 3. New recent hash and a new shard land in the delta only.
	fs.mu.Lock()
	fs.recent = append(fs.recent, h("r2"))
	fs.shards = append(fs.shards, []string{m("v3")})
	fs.mu.Unlock()
	baseInfo, _ := os.Stat(scanner.DBPath(cfg))
	rep, err = Run(ctx, cfg, Options{})
	if err != nil || !rep.Changed || rep.After != 7 {
		t.Fatalf("incremental: %+v %v", rep, err)
	}
	if after, _ := os.Stat(scanner.DBPath(cfg)); !after.ModTime().Equal(baseInfo.ModTime()) {
		t.Fatal("incremental update rewrote the base database")
	}
	s := lookup(t, cfg)
	for _, x := range []string{h("a"), h("r2"), m("v1"), m("v3")} {
		if !has(s, x) {
			t.Fatalf("missing %s after incremental", x)
		}
	}

	// 4. Full refresh: the full feed's entries are replaced (h("a") dropped
	// upstream), other sources are kept, the delta is folded in.
	fs.mu.Lock()
	fs.full = []string{h("b"), h("c")}
	fs.mu.Unlock()
	rep, err = Run(ctx, cfg, Options{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	s = lookup(t, cfg)
	if has(s, h("a")) || !has(s, h("c")) || !has(s, h("r1")) || !has(s, m("v3")) {
		t.Fatal("full refresh did not replace/keep entries per source")
	}
	if _, err := os.Stat(scanner.DeltaPath(cfg)); err == nil {
		t.Fatal("delta not folded into base on full refresh")
	}

	// 5. A failing full feed keeps its previous entries.
	fs.mu.Lock()
	fs.fail = true
	fs.mu.Unlock()
	if _, err := Run(ctx, cfg, Options{Force: true}); err != nil {
		t.Fatal(err)
	}
	if s = lookup(t, cfg); !has(s, h("c")) {
		t.Fatal("failed full feed lost its entries")
	}
	if LoadState(cfg).Feeds["full"].LastError == "" {
		t.Fatal("feed error not recorded")
	}

	// 6. Disabling a feed purges its entries on the next full rebuild.
	fs.mu.Lock()
	fs.fail = false
	fs.mu.Unlock()
	cfg.Feeds[2].Enabled = false
	if _, err := Run(ctx, cfg, Options{Force: true}); err != nil {
		t.Fatal(err)
	}
	if s = lookup(t, cfg); has(s, m("v1")) {
		t.Fatal("disabled feed's entries kept")
	}
}

func TestAllFeedsFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer ts.Close()
	cfg := config.Default(t.TempDir())
	cfg.Feeds = []config.Feed{{Name: "x", URL: ts.URL, Format: "text", Refresh: "full", Enabled: true}}
	if _, err := Run(context.Background(), cfg, Options{}); err == nil {
		t.Fatal("expected error when every feed fails")
	}
}

func TestCheck(t *testing.T) {
	cfg, _ := setup(t)
	// No database: an update is needed.
	if rd := Check(cfg, 0); rd.Ready || !rd.NeedUpdate {
		t.Fatalf("missing DB: %+v", rd)
	}
	if _, err := Run(context.Background(), cfg, Options{}); err != nil {
		t.Fatal(err)
	}
	if rd := Check(cfg, 5); !rd.Ready {
		t.Fatalf("fresh DB: %+v", rd)
	}
	// Stale database.
	cfg.Policy.MaxSignatureAge = config.Duration{Duration: time.Nanosecond}
	time.Sleep(time.Millisecond)
	if rd := Check(cfg, 5); rd.Ready || !rd.NeedUpdate {
		t.Fatalf("stale DB: %+v", rd)
	}
	// While an update holds the lock: retry, don't start another.
	unlock, err := lock(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if rd := Check(cfg, 5); !rd.Updating || rd.NeedUpdate {
		t.Fatalf("during update: %+v", rd)
	}
	unlock()
	// A recent failed attempt reports an error instead of looping on retry.
	st := LoadState(cfg)
	st.LastAttempt, st.LastError = time.Now(), "HTTP 503"
	saveState(cfg, st)
	if rd := Check(cfg, 5); rd.Err == nil {
		t.Fatalf("after failure: %+v", rd)
	}
	// Signatures not required: always ready.
	cfg.Policy.RequireSignatures = false
	if rd := Check(cfg, 0); !rd.Ready {
		t.Fatalf("not required: %+v", rd)
	}
}
