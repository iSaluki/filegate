package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/sigdb"
)

func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*")
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default(t.TempDir())
	cfg.ClamAV.Enabled = "off"
	cfg.Limits.MaxFileSize = 8 << 20
	cfg.Limits.MaxTotalExtract = 64 << 20
	return cfg
}

func newScanner(t *testing.T, cfg *config.Config) *Scanner {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mkzip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	zw.Close()
	return b.Bytes()
}

func mktgz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}

func TestSafeFile(t *testing.T) {
	s := newScanner(t, testConfig(t))
	r := s.ScanBytes(context.Background(), "hello.txt", []byte("hello world\n"))
	if r.Verdict != VerdictSafe || len(r.Detections) != 0 {
		t.Fatalf("expected safe, got %+v", r)
	}
}

func TestNestedArchive(t *testing.T) {
	s := newScanner(t, testConfig(t))
	inner := mkzip(t, map[string][]byte{"docs/readme.txt": []byte("hi"), "payload/eicar.com": eicar()})
	outer := mktgz(t, map[string][]byte{"bundle/inner.zip": inner, "ok.txt": []byte("fine")})
	r := s.ScanBytes(context.Background(), "release.tar.gz", outer)
	if !r.Malicious() {
		t.Fatalf("EICAR in zip in tar.gz not detected: %+v", r)
	}
	want := "release.tar.gz!release.tar!bundle/inner.zip!payload/eicar.com"
	if r.Detections[0].Object != want {
		t.Errorf("object path = %q, want %q", r.Detections[0].Object, want)
	}
	if r.ObjectsScanned < 6 {
		t.Errorf("objects scanned = %d", r.ObjectsScanned)
	}
}

func TestZipBomb(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxFileSize = 1 << 20
	s := newScanner(t, cfg)
	bomb := mkzip(t, map[string][]byte{"zeros.bin": make([]byte, 16<<20)})
	r := s.ScanBytes(context.Background(), "bomb.zip", bomb)
	if !r.Malicious() || r.Detections[0].Name != "Heuristic.Archive.Bomb" {
		t.Fatalf("zip bomb not detected: %+v", r)
	}
}

func TestRecursionDepth(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxArchiveDepth = 3
	s := newScanner(t, cfg)
	data := []byte("x")
	for i := 0; i < 6; i++ {
		data = mkzip(t, map[string][]byte{"l.zip": data})
	}
	r := s.ScanBytes(context.Background(), "deep.zip", data)
	found := false
	for _, d := range r.Detections {
		if d.Name == "Heuristic.Archive.TooDeep" {
			found = true
		}
	}
	if !found {
		t.Fatalf("depth limit not reported: %+v", r)
	}
}

func TestEncryptedExecutable(t *testing.T) {
	s := newScanner(t, testConfig(t))
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "invoice.exe", Method: zip.Store, Flags: 0x1})
	w.Write([]byte("encrypted-garbage"))
	zw.Close()
	r := s.ScanBytes(context.Background(), "invoice.zip", b.Bytes())
	if !r.Malicious() {
		t.Fatalf("encrypted executable archive not flagged: %+v", r)
	}
}

func TestHashSignatureAndAllowlist(t *testing.T) {
	cfg := testConfig(t)
	sample := []byte("pretend this is a known malware sample")
	sum := sha256.Sum256(sample)

	b := sigdb.NewBuilder()
	b.Add(sum, "testfeed")
	if err := b.Write(DBPath(cfg)); err != nil {
		t.Fatal(err)
	}
	s := newScanner(t, cfg)
	r := s.ScanBytes(context.Background(), "x.bin", sample)
	if !r.Malicious() || r.Detections[0].Engine != EngineSignature || !strings.Contains(r.Detections[0].Name, "testfeed") {
		t.Fatalf("hash signature not matched: %+v", r)
	}

	// Inside an archive too.
	r = s.ScanBytes(context.Background(), "x.zip", mkzip(t, map[string][]byte{"a/b.bin": sample}))
	if !r.Malicious() {
		t.Fatalf("hash signature inside zip not matched: %+v", r)
	}

	// Allowlisting the hash overrides the signature.
	os.MkdirAll(AllowlistDir(cfg), 0o755)
	os.WriteFile(filepath.Join(AllowlistDir(cfg), "fp.txt"), []byte(hex.EncodeToString(sum[:])+" false positive\n"), 0o644)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	r = s.ScanBytes(context.Background(), "x.bin", sample)
	if r.Malicious() || !r.Allowlisted {
		t.Fatalf("allowlist not honoured: %+v", r)
	}
}

func TestCustomSignature(t *testing.T) {
	cfg := testConfig(t)
	sample := []byte("internal red-team payload")
	sum := sha256.Sum256(sample)
	os.MkdirAll(CustomSigDir(cfg), 0o755)
	os.WriteFile(filepath.Join(CustomSigDir(cfg), "local.txt"), []byte("# comment\n"+hex.EncodeToString(sum[:])+" RedTeam.Implant\n"), 0o644)
	s := newScanner(t, cfg)
	r := s.ScanBytes(context.Background(), "p.bin", sample)
	if !r.Malicious() || r.Detections[0].Name != "RedTeam.Implant" {
		t.Fatalf("custom signature not matched: %+v", r)
	}
}

func TestScanFileLarge(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxFileSize = 1024
	s := newScanner(t, cfg)
	p := filepath.Join(t.TempDir(), "big.bin")
	os.WriteFile(p, bytes.Repeat([]byte("A"), 4096), 0o644)
	r, err := s.ScanFile(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != VerdictSafe || len(r.Warnings) == 0 || r.Size != 4096 {
		t.Fatalf("unexpected result for large file: %+v", r)
	}
}

func TestGzipBomb(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxFileSize = 1 << 20
	s := newScanner(t, cfg)
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write(make([]byte, 64<<20))
	gz.Close()
	r := s.ScanBytes(context.Background(), "zeros.gz", b.Bytes())
	if !r.Malicious() || r.Detections[0].Name != "Heuristic.Archive.Bomb" {
		t.Fatalf("gzip bomb not detected: %+v", r)
	}
}

func TestWindowsExecutableMasquerade(t *testing.T) {
	// Real PE files shipped with the Go toolchain's debug/pe tests.
	files, _ := filepath.Glob(filepath.Join(runtime.GOROOT(), "src/debug/pe/testdata/*-exec"))
	if len(files) == 0 {
		t.Skip("no PE test binaries in GOROOT")
	}
	s := newScanner(t, testConfig(t))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		if r := s.ScanBytes(context.Background(), filepath.Base(f), data); r.Malicious() {
			t.Errorf("%s: benign PE flagged: %+v", f, r.Detections)
		}
	}
	data, _ := os.ReadFile(files[0])
	r := s.ScanBytes(context.Background(), "Invoice_2024.pdf.exe", data)
	if !r.Malicious() {
		t.Errorf("double-extension PE not flagged: %+v", r.Detections)
	}
}
