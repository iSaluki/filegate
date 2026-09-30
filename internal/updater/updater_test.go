package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
)

func h(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestFullThenIncremental(t *testing.T) {
	var fullFail atomic.Bool
	recent := "# recent\n" + h("r1") + "\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/full", func(w http.ResponseWriter, r *http.Request) {
		if fullFail.Load() {
			http.Error(w, "down", 503)
			return
		}
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		f, _ := zw.Create("full_sha256.txt")
		fmt.Fprintf(f, "# header\n%s\n%s\n", h("a"), h("b"))
		zw.Close()
		w.Write(b.Bytes())
	})
	mux.HandleFunc("/recent", func(w http.ResponseWriter, r *http.Request) {
		etag := fmt.Sprintf("%q", h(recent)[:8])
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		fmt.Fprint(w, recent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := config.Default(t.TempDir())
	cfg.Feeds = []config.Feed{
		{Name: "full", URL: ts.URL + "/full", Format: "zip", Refresh: "full", Enabled: true},
		{Name: "recent", URL: ts.URL + "/recent", Format: "text", Refresh: "incremental", Enabled: true},
	}
	ctx := context.Background()

	rep, err := Run(ctx, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Full || rep.After != 3 || !rep.Changed {
		t.Fatalf("first run: %+v", rep)
	}

	// Second run: incremental, recent feed unchanged (304) -> no rewrite.
	rep, err = Run(ctx, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Full || rep.Changed || rep.After != 3 || !rep.Feeds[1].NotModified {
		t.Fatalf("second run: %+v", rep)
	}

	// New recent hash is merged with existing ones.
	recent += h("r2") + "\n"
	rep, err = Run(ctx, cfg, Options{})
	if err != nil || rep.After != 4 || !rep.Changed {
		t.Fatalf("third run: %+v %v", rep, err)
	}

	// Forced full rebuild where the full feed fails keeps existing hashes.
	fullFail.Store(true)
	rep, err = Run(ctx, cfg, Options{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.After != 4 {
		t.Fatalf("failed full rebuild lost hashes: %+v", rep)
	}
	db, err := sigdb.Open(scanner.DBPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var want sigdb.Hash
	sum := sha256.Sum256([]byte("a"))
	copy(want[:], sum[:])
	if src, ok := db.Lookup(want); !ok || src != "full" {
		t.Fatalf("lookup = %q %v", src, ok)
	}
	if st := LoadState(cfg); st.Feeds["full"].LastError == "" {
		t.Fatal("feed error not recorded in state")
	}
}

func TestAllFeedsFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer ts.Close()
	cfg := config.Default(t.TempDir())
	cfg.Feeds = []config.Feed{{Name: "x", URL: ts.URL, Format: "text", Refresh: "incremental", Enabled: true}}
	if _, err := Run(context.Background(), cfg, Options{}); err == nil {
		t.Fatal("expected error when every feed fails")
	}
}
