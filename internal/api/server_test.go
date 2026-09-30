package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/isaluki/filegate/internal/apikey"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
)

func setup(t *testing.T) (*httptest.Server, string, *apikey.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "data"))
	cfg.SetPath(filepath.Join(dir, "config.json"))
	cfg.ClamAV.Enabled = "off"
	cfg.API.MaxUploadSize = 1 << 20
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := apikey.NewStore(cfg.KeysPath())
	key, _, err := store.Create("test", 0)
	if err != nil {
		t.Fatal(err)
	}
	v, err := apikey.NewVerifier(store)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, sc, v, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, key, store
}

func do(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*")
}

func TestAuth(t *testing.T) {
	ts, key, _ := setup(t)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/health", nil)
	if code, _ := do(t, req); code != 200 {
		t.Fatalf("health = %d", code)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/v1/scan", bytes.NewReader([]byte("x")))
	if code, _ := do(t, req); code != 401 {
		t.Fatalf("no key = %d", code)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/v1/scan", bytes.NewReader([]byte("x")))
	req.Header.Set("Authorization", "Bearer fg_wrong")
	if code, _ := do(t, req); code != 401 {
		t.Fatalf("bad key = %d", code)
	}
	req, _ = http.NewRequest("GET", ts.URL+"/v1/status", nil)
	req.Header.Set("X-API-Key", key)
	if code, m := do(t, req); code != 200 || m["engines"] == nil {
		t.Fatalf("status = %d %v", code, m)
	}
}

func TestScanRawAndMultipart(t *testing.T) {
	ts, key, _ := setup(t)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/scan?filename=eicar.com", bytes.NewReader(eicar()))
	req.Header.Set("Authorization", "Bearer "+key)
	code, m := do(t, req)
	if code != 200 || m["verdict"] != "malicious" || m["file"] != "eicar.com" {
		t.Fatalf("raw scan = %d %v", code, m)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "notes.txt")
	fw.Write([]byte("just some notes"))
	mw.Close()
	req, _ = http.NewRequest("POST", ts.URL+"/v1/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+key)
	code, m = do(t, req)
	if code != 200 || m["verdict"] != "safe" || m["file"] != "notes.txt" {
		t.Fatalf("multipart scan = %d %v", code, m)
	}
}

func TestUploadLimitAndRevocation(t *testing.T) {
	ts, key, store := setup(t)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/scan", bytes.NewReader(make([]byte, 2<<20)))
	req.Header.Set("Authorization", "Bearer "+key)
	if code, _ := do(t, req); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d", code)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/v1/hash/"+"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	if code, m := do(t, req); code != 200 || m["known"] != false {
		t.Fatalf("hash lookup = %d %v", code, m)
	}

	if _, err := store.Revoke("test"); err != nil {
		t.Fatal(err)
	}
	// The verifier re-reads the store; force past its 2s cache by creating a fresh request after mtime change.
	v, _ := apikey.NewVerifier(store)
	if _, ok := v.Verify(key); ok {
		t.Fatal("revoked key still valid")
	}
}
