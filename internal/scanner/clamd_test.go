package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeClamd speaks enough of the clamd protocol for tests: PING, VERSION and
// INSTREAM. Streams containing marker are reported as infected.
type fakeClamd struct {
	path   string
	scans  atomic.Int32
	marker []byte
}

func startFakeClamd(t *testing.T, marker string) *fakeClamd {
	t.Helper()
	dir, err := os.MkdirTemp("", "clamd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeClamd{path: filepath.Join(dir, "clamd.sock"), marker: []byte(marker)}
	l, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeClamd) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	cmd, err := r.ReadString(0)
	if err != nil {
		return
	}
	switch strings.TrimRight(cmd, "\x00") {
	case "zPING":
		c.Write([]byte("PONG\x00"))
	case "zVERSION":
		c.Write([]byte("ClamAV 1.4.3/27777/Fake\x00"))
	case "zINSTREAM":
		f.scans.Add(1)
		var data bytes.Buffer
		for {
			var hdr [4]byte
			if _, err := io.ReadFull(r, hdr[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr[:])
			if n == 0 {
				break
			}
			io.CopyN(&data, r, int64(n))
		}
		if bytes.Contains(data.Bytes(), f.marker) {
			c.Write([]byte("stream: Fake.Malware.Sig FOUND\x00"))
		} else {
			c.Write([]byte("stream: OK\x00"))
		}
	}
}

func TestClamAVRequiredButMissing(t *testing.T) {
	cfg := testConfig(t)
	cfg.ClamAV.Enabled = "required"
	cfg.ClamAV.Socket = filepath.Join(t.TempDir(), "absent.sock")
	s := newScanner(t, cfg)
	err := s.ClamAVReady(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ClamAV is required") {
		t.Fatalf("ClamAVReady = %v", err)
	}
	r := s.ScanBytes(context.Background(), "a.txt", []byte("hello"))
	if r.Verdict != VerdictError || !strings.Contains(r.Error, "ClamAV is required") {
		t.Fatalf("scan without clamd = %+v", r)
	}
}

func TestClamAVDetection(t *testing.T) {
	fc := startFakeClamd(t, "CLAMD-TEST-MARKER")
	cfg := testConfig(t)
	cfg.ClamAV.Enabled = "required"
	cfg.ClamAV.Socket = fc.path
	s := newScanner(t, cfg)
	if err := s.ClamAVReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := s.ScanBytes(context.Background(), "ok.txt", []byte("hello")); r.Verdict != VerdictSafe {
		t.Fatalf("clean file = %+v", r)
	}
	r := s.ScanBytes(context.Background(), "bad.bin", []byte("xx CLAMD-TEST-MARKER xx"))
	if !r.Malicious() || r.Detections[0].Engine != EngineClamAV || r.Detections[0].Name != "Fake.Malware.Sig" {
		t.Fatalf("clamd detection = %+v", r)
	}
	// 7z is covered when ClamAV scanned the file.
	sevenZip := append([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 64)...)
	if r := s.ScanBytes(context.Background(), "a.7z", sevenZip); r.Verdict != VerdictSafe {
		t.Fatalf("7z with ClamAV = %+v", r)
	}
}

func TestClamAVSeesDecryptedMembers(t *testing.T) {
	// ClamAV cannot open password-protected archives, so FileGate sends the
	// decrypted member to it directly.
	fc := startFakeClamd(t, "harmless stand-in")
	cfg := testConfig(t)
	cfg.ClamAV.Enabled = "required"
	cfg.ClamAV.Socket = fc.path
	s := newScanner(t, cfg)
	data, _ := os.ReadFile(filepath.Join("testdata", "aes256-infected-deflate.zip"))
	r := s.ScanBytesWith(context.Background(), "s.zip", data, Options{Password: "infected"})
	if !r.Malicious() || r.Detections[0].Engine != EngineClamAV || !strings.HasSuffix(r.Detections[0].Object, "standin.elf") {
		t.Fatalf("decrypted member not sent to ClamAV: %+v", r)
	}
	if fc.scans.Load() != 2 {
		t.Fatalf("clamd scans = %d, want 2 (archive + decrypted member)", fc.scans.Load())
	}
}
