package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/isaluki/filegate/internal/archive"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/sigdb"
)

func eicar() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*")
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default(t.TempDir())
	cfg.ClamAV.Enabled = "off" // tests that need ClamAV use a fake clamd
	cfg.Limits.MaxFileSize = 8 << 20
	cfg.Limits.MaxTotalExtract = 64 << 20
	// A loaded signature DB is required for trustworthy verdicts.
	writeDB(t, DBPath(cfg), func(b *sigdb.Builder) { b.Add(sha256.Sum256([]byte("unrelated")), "fixture") })
	return cfg
}

func writeDB(t *testing.T, path string, fill func(*sigdb.Builder)) {
	t.Helper()
	b, err := sigdb.NewBuilder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	fill(b)
	if _, err := b.Write(path); err != nil {
		t.Fatal(err)
	}
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
	if r.Verdict != VerdictError || r.Error != archive.ErrPasswordProtected {
		t.Fatalf("encrypted archive without password = %+v", r)
	}
}

func TestHashSignatureAndAllowlist(t *testing.T) {
	cfg := testConfig(t)
	sample := []byte("pretend this is a known malware sample")
	sum := sha256.Sum256(sample)

	writeDB(t, DBPath(cfg), func(b *sigdb.Builder) { b.Add(sum, "testfeed") })
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
	// Too large to analyse and no ClamAV: must not be reported as safe.
	if r.Verdict != VerdictError || r.Size != 4096 {
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

// standin mirrors testdata/*.zip content: a harmless file standing in for a
// known malware sample, as distributed in password-protected archives.
func standin() []byte {
	return bytes.Repeat([]byte("FileGate harmless stand-in for a known malware sample. Do not flag by content.\n"), 20)
}

func withStandinSignature(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	sum := sha256.Sum256(standin())
	os.MkdirAll(CustomSigDir(cfg), 0o755)
	os.WriteFile(filepath.Join(CustomSigDir(cfg), "t.txt"), []byte(hex.EncodeToString(sum[:])+" Standin.KnownSample\n"), 0o644)
	return cfg
}

func TestEncryptedSampleArchives(t *testing.T) {
	s := newScanner(t, withStandinSignature(t))
	// Fixtures were produced by independent tools: pyzipper (WinZip AES)
	// and Info-ZIP `zip -P` (ZipCrypto).
	cases := []struct{ file, password string }{
		{"aes256-infected-deflate.zip", "infected"},
		{"aes128-malware-stored.zip", "malware"},
		{"zipcrypto-infected.zip", "infected"},
		{"zipcrypto-virus-stored.zip", "virus"},
		{"aes256-unknownpw.zip", "s3cret-Pw!"},
		{"zipcrypto-unknownpw.zip", "hunter2"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			// Correct password: the member is decrypted and matched.
			r := s.ScanBytesWith(context.Background(), c.file, data, Options{Password: c.password})
			if !r.Malicious() || r.Detections[0].Name != "Standin.KnownSample" {
				t.Fatalf("with password: %+v", r)
			}
			// No password, or a wrong one: never guessed, never "safe".
			for _, pw := range []string{"", "wrong-password"} {
				r := s.ScanBytesWith(context.Background(), c.file, data, Options{Password: pw})
				if r.Verdict != VerdictError || r.Error != archive.ErrPasswordProtected {
					t.Fatalf("password %q: verdict %s error %q", pw, r.Verdict, r.Error)
				}
			}
		})
	}
	// Common sample passwords are not tried automatically.
	data, _ := os.ReadFile(filepath.Join("testdata", "zipcrypto-infected.zip"))
	if r := s.ScanBytes(context.Background(), "z.zip", data); r.Verdict != VerdictError {
		t.Fatalf("no-password scan guessed the password: %+v", r)
	}
}

func TestMD5Signature(t *testing.T) {
	cfg := testConfig(t)
	sample := []byte("sample only known by MD5 (e.g. VirusShare)")
	writeDB(t, DeltaPath(cfg), func(b *sigdb.Builder) { b.AddMD5(md5.Sum(sample), "virusshare") })
	s := newScanner(t, cfg)
	r := s.ScanBytes(context.Background(), "x.bin", sample)
	if !r.Malicious() || r.Detections[0].Name != "Malware.MD5.virusshare" {
		t.Fatalf("MD5 signature not matched: %+v", r)
	}
	// An MD5 allowlist entry must NOT override (MD5 collisions are practical).
	os.MkdirAll(AllowlistDir(cfg), 0o755)
	m := md5.Sum(sample)
	os.WriteFile(filepath.Join(AllowlistDir(cfg), "a.txt"), []byte(hex.EncodeToString(m[:])+"\n"), 0o644)
	s.Reload()
	if r := s.ScanBytes(context.Background(), "x.bin", sample); !r.Malicious() {
		t.Fatalf("MD5 allowlist entry was honoured: %+v", r)
	}
}

func TestNoSignatureDBIsError(t *testing.T) {
	cfg := config.Default(t.TempDir())
	cfg.ClamAV.Enabled = "off"
	s := newScanner(t, cfg)
	if s.Ready() == nil {
		t.Fatal("Ready() should fail without a signature database")
	}
	if r := s.ScanBytes(context.Background(), "a.txt", []byte("hello")); r.Verdict != VerdictError {
		t.Fatalf("scan without DB = %s, want error", r.Verdict)
	}
	// A positive detection is still reported.
	if r := s.ScanBytes(context.Background(), "e.com", eicar()); r.Verdict != VerdictMalicious {
		t.Fatalf("EICAR without DB = %s, want malicious", r.Verdict)
	}
}

func TestUnsupportedContainerIsError(t *testing.T) {
	s := newScanner(t, testConfig(t))
	sevenZip := append([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 64)...)
	if r := s.ScanBytes(context.Background(), "samples.7z", sevenZip); r.Verdict != VerdictError {
		t.Fatalf("7z without ClamAV = %s, want error", r.Verdict)
	}
	// Nested inside a zip too.
	if r := s.ScanBytes(context.Background(), "x.zip", mkzip(t, map[string][]byte{"in.7z": sevenZip})); r.Verdict != VerdictError {
		t.Fatalf("nested 7z = %s, want error", r.Verdict)
	}
}

func TestEncryptedOfficeIsError(t *testing.T) {
	s := newScanner(t, testConfig(t))
	doc := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	doc = append(doc, make([]byte, 100)...)
	for _, r := range "EncryptedPackage" {
		doc = append(doc, byte(r), 0)
	}
	if r := s.ScanBytes(context.Background(), "invoice.docx", doc); r.Verdict != VerdictError {
		t.Fatalf("encrypted Office doc = %s, want error", r.Verdict)
	}
}

func TestUnscannablePolicyMalicious(t *testing.T) {
	cfg := testConfig(t)
	cfg.Policy.Unscannable = "malicious"
	s := newScanner(t, cfg)
	data, _ := os.ReadFile(filepath.Join("testdata", "aes256-unknownpw.zip"))
	if r := s.ScanBytes(context.Background(), "x.zip", data); r.Verdict != VerdictMalicious {
		t.Fatalf("policy=malicious gave %s", r.Verdict)
	}
}

func TestTruncatedMemberIsError(t *testing.T) {
	cfg := testConfig(t)
	cfg.Limits.MaxFileSize = 1024
	s := newScanner(t, cfg)
	// Incompressible data larger than the per-object limit: not a bomb, but
	// not fully inspected either (padding would otherwise hide a payload).
	big := make([]byte, 8192)
	for i := range big {
		big[i] = byte(i*7919 + i>>3)
	}
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "big.bin", Method: zip.Store})
	w.Write(big)
	zw.Close()
	if r := s.ScanBytes(context.Background(), "pad.zip", b.Bytes()); r.Verdict != VerdictError {
		t.Fatalf("truncated member = %s, want error", r.Verdict)
	}
}
