package api

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/isaluki/filegate/internal/apikey"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
)

func setup(t *testing.T) (*httptest.Server, string, *apikey.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "data"))
	cfg.SetPath(filepath.Join(dir, "config.json"))
	cfg.ClamAV.Enabled = "off"
	cfg.API.MaxUploadSize = 1 << 20
	b, err := sigdb.NewBuilder(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Add(sha256.Sum256([]byte("unrelated")), "fixture")
	b.AddMD5(md5.Sum([]byte("known-by-md5")), "virusshare")
	os.MkdirAll(cfg.DataDir, 0o755)
	if _, err := b.Write(scanner.DBPath(cfg)); err != nil {
		t.Fatal(err)
	}
	b.Close()
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

func TestUnscannableReturns422(t *testing.T) {
	ts, key, _ := setup(t)
	sevenZip := append([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 64)...)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/scan?filename=a.7z", bytes.NewReader(sevenZip))
	req.Header.Set("Authorization", "Bearer "+key)
	code, m := do(t, req)
	if code != http.StatusUnprocessableEntity || m["verdict"] != "error" || m["error"] == nil {
		t.Fatalf("7z scan = %d %v", code, m)
	}
}

func TestHashLookup(t *testing.T) {
	ts, key, _ := setup(t)
	get := func(h string) (int, map[string]any) {
		req, _ := http.NewRequest("GET", ts.URL+"/v1/hash/"+h, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		return do(t, req)
	}
	m5 := md5.Sum([]byte("known-by-md5"))
	if code, m := get(hex.EncodeToString(m5[:])); code != 200 || m["verdict"] != "malicious" {
		t.Fatalf("md5 lookup = %d %v", code, m)
	}
	// Unknown hashes are "unknown", never "safe".
	if code, m := get(strings.Repeat("ab", 32)); code != 200 || m["verdict"] != "unknown" {
		t.Fatalf("unknown lookup = %d %v", code, m)
	}
	if code, _ := get("nothex"); code != 400 {
		t.Fatalf("bad hash = %d", code)
	}
}

func TestPasswordProtectedUpload(t *testing.T) {
	ts, key, _ := setup(t)
	data, err := os.ReadFile("../scanner/testdata/zipcrypto-infected.zip")
	if err != nil {
		t.Fatal(err)
	}
	// Without a password: error with the exact note.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/scan?filename=s.zip", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+key)
	code, m := do(t, req)
	if code != http.StatusUnprocessableEntity || m["verdict"] != "error" ||
		m["error"] != "Archive is password protected and no valid password was specified" {
		t.Fatalf("no password = %d %v", code, m)
	}
	// Header password.
	req, _ = http.NewRequest("POST", ts.URL+"/v1/scan?filename=s.zip", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Archive-Password", "infected")
	if code, m := do(t, req); code != 200 || m["verdict"] != "safe" || m["objects_scanned"].(float64) != 2 {
		t.Fatalf("header password = %d %v", code, m)
	}
	// Multipart password field, sent after the file part.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "s.zip")
	fw.Write(data)
	mw.WriteField("password", "infected")
	mw.Close()
	req, _ = http.NewRequest("POST", ts.URL+"/v1/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+key)
	if code, m := do(t, req); code != 200 || m["verdict"] != "safe" {
		t.Fatalf("multipart password = %d %v", code, m)
	}
}

func TestRetryWhileDatabaseDownloads(t *testing.T) {
	release := make(chan struct{})
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the update until the test has seen "retry"
		fmt.Fprintln(w, strings.Repeat("cd", 32))
	}))
	defer feed.Close()

	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "data"))
	cfg.SetPath(filepath.Join(dir, "config.json"))
	cfg.ClamAV.Enabled = "off"
	cfg.Feeds = []config.Feed{{Name: "f", URL: feed.URL, Format: "text", Refresh: "full", Enabled: true}}
	sc, _ := scanner.New(cfg)
	store := apikey.NewStore(cfg.KeysPath())
	key, _, _ := store.Create("t", 0)
	v, _ := apikey.NewVerifier(store)
	ts := httptest.NewServer(New(cfg, sc, v, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Handler())
	defer ts.Close()

	scan := func() (int, map[string]any, http.Header) {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/scan?filename=a.txt", strings.NewReader("hello"))
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m, resp.Header
	}
	code, m, hdr := scan()
	if code != http.StatusServiceUnavailable || m["verdict"] != "retry" || hdr.Get("Retry-After") == "" {
		t.Fatalf("first scan = %d %v", code, m)
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, m, _ = scan()
		if code == 200 {
			break
		}
		if m["verdict"] != "retry" || time.Now().After(deadline) {
			t.Fatalf("scan during update = %d %v", code, m)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if m["verdict"] != "safe" {
		t.Fatalf("scan after update = %v", m)
	}
}

func setupAnonymous(t *testing.T, mutate func(*config.Config)) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(filepath.Join(dir, "data"))
	cfg.SetPath(filepath.Join(dir, "config.json"))
	cfg.ClamAV.Enabled = "off"
	cfg.API.Anonymous.Enabled = true
	cfg.API.Anonymous.MaxUploadSize = 1024
	cfg.API.Anonymous.RequestsPerMinute = 60
	cfg.API.Anonymous.Burst = 3
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := sigdb.NewBuilder(dir)
	b.Add(sha256.Sum256([]byte("unrelated")), "fixture")
	os.MkdirAll(cfg.DataDir, 0o755)
	b.Write(scanner.DBPath(cfg))
	b.Close()
	sc, _ := scanner.New(cfg)
	store := apikey.NewStore(cfg.KeysPath())
	key, _, _ := store.Create("t", 0)
	v, _ := apikey.NewVerifier(store)
	ts := httptest.NewServer(New(cfg, sc, v, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Handler())
	t.Cleanup(ts.Close)
	return ts, key
}

func post(t *testing.T, url string, body []byte, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m, resp.Header
}

func TestAnonymousDisabledByDefault(t *testing.T) {
	ts, _, _ := setup(t)
	if code, _, _ := post(t, ts.URL+"/v1/scan", []byte("hi"), nil); code != 401 {
		t.Fatalf("anonymous scan with anonymous disabled = %d", code)
	}
}

func TestAnonymousAccess(t *testing.T) {
	ts, key := setupAnonymous(t, nil)
	// No key: allowed, and gets a real verdict.
	code, m, _ := post(t, ts.URL+"/v1/scan?filename=e.com", eicar(), nil)
	if code != 200 || m["verdict"] != "malicious" {
		t.Fatalf("anonymous scan = %d %v", code, m)
	}
	// An invalid key is rejected, not downgraded to anonymous.
	if code, _, _ := post(t, ts.URL+"/v1/scan", []byte("hi"), map[string]string{"X-API-Key": "fg_bogus"}); code != 401 {
		t.Fatalf("invalid key = %d", code)
	}
	// Anonymous upload cap; a valid key lifts it.
	big := bytes.Repeat([]byte("a"), 4096)
	if code, m, _ := post(t, ts.URL+"/v1/scan", big, nil); code != 413 || !strings.Contains(m["error"].(string), "API key") {
		t.Fatalf("anonymous oversize = %d %v", code, m)
	}
	if code, _, _ := post(t, ts.URL+"/v1/scan", big, map[string]string{"X-API-Key": key}); code != 200 {
		t.Fatalf("keyed large upload = %d", code)
	}
	// Status stays key-only.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/status", nil)
	if code, _ := do(t, req); code != 401 {
		t.Fatalf("anonymous status = %d", code)
	}
}

func TestAnonymousRateLimit(t *testing.T) {
	ts, key := setupAnonymous(t, nil)
	var code int
	var hdr http.Header
	for i := 0; i < 5; i++ { // burst is 3 (two requests above already used none)
		code, _, hdr = post(t, ts.URL+"/v1/scan", []byte("hi"), nil)
		if code == http.StatusTooManyRequests {
			break
		}
	}
	if code != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Fatalf("rate limit not enforced: %d", code)
	}
	// Keyed clients are not rate limited.
	if code, _, _ := post(t, ts.URL+"/v1/scan", []byte("hi"), map[string]string{"X-API-Key": key}); code != 200 {
		t.Fatalf("keyed scan while anonymous limited = %d", code)
	}
}

func TestSpoofedForwardedForDoesNotEvadeLimit(t *testing.T) {
	ts, _ := setupAnonymous(t, func(c *config.Config) { c.API.TrustProxyHeaders = true })
	// The proxy appends the real client (here: a fixed IP) as the LAST
	// entry; the client controls everything before it.
	limited := false
	for i := 0; i < 6; i++ {
		xff := fmt.Sprintf("10.9.9.%d, 198.51.100.7", i)
		if code, _, _ := post(t, ts.URL+"/v1/scan", []byte("hi"), map[string]string{"X-Forwarded-For": xff}); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("rotating the client-controlled X-Forwarded-For prefix evaded the rate limit")
	}
}

func TestClientIPHeader(t *testing.T) {
	ts, _ := setupAnonymous(t, func(c *config.Config) { c.API.ClientIPHeader = "CF-Connecting-IP" })
	// Distinct clients behind Cloudflare each get their own budget.
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		if code, _, _ := post(t, ts.URL+"/v1/scan", []byte("hi"), map[string]string{"CF-Connecting-IP": ip}); code != 200 {
			t.Fatalf("client %s = %d", ip, code)
		}
	}
}
