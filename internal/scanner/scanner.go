// Package scanner orchestrates FileGate's detection engines: the SHA-256
// signature database, local custom signatures, the heuristic engine,
// recursive archive unpacking and (optionally) ClamAV.
package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/isaluki/filegate/internal/archive"
	"github.com/isaluki/filegate/internal/clamav"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/heuristics"
	"github.com/isaluki/filegate/internal/sigdb"
)

const (
	VerdictSafe      = "safe"
	VerdictMalicious = "malicious"

	EngineSignature = "signature"
	EngineCustom    = "custom-signature"
	EngineHeuristic = "heuristic"
	EngineArchive   = "archive"
	EngineClamAV    = "clamav"
)

// Detection is a single engine hit.
type Detection struct {
	Engine      string `json:"engine"`
	Name        string `json:"name"`
	Object      string `json:"object"`
	Score       int    `json:"score"`
	Description string `json:"description,omitempty"`
}

// Result is the outcome of scanning one file.
type Result struct {
	File           string      `json:"file"`
	Size           int64       `json:"size"`
	SHA256         string      `json:"sha256"`
	Type           string      `json:"type"`
	Verdict        string      `json:"verdict"`
	Score          int         `json:"score"`
	Detections     []Detection `json:"detections"`
	ObjectsScanned int         `json:"objects_scanned"`
	Warnings       []string    `json:"warnings,omitempty"`
	Allowlisted    bool        `json:"allowlisted,omitempty"`
	DurationMS     float64     `json:"duration_ms"`
}

// Malicious reports whether the verdict is malicious.
func (r *Result) Malicious() bool { return r.Verdict == VerdictMalicious }

// Scanner is safe for concurrent use.
type Scanner struct {
	cfg    *config.Config
	db     atomic.Pointer[sigdb.DB]
	custom atomic.Pointer[sigdb.LocalList]
	allow  atomic.Pointer[sigdb.LocalList]
	clam   *clamav.Client
	mu     sync.Mutex // serialises reloads
}

// Paths within the data directory.
func DBPath(cfg *config.Config) string       { return filepath.Join(cfg.DataDir, "hashes.fgdb") }
func CustomSigDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "signatures") }
func AllowlistDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "allowlist") }
func UpdateStatePath(cfg *config.Config) string {
	return filepath.Join(cfg.DataDir, "update-state.json")
}

// New creates a scanner and loads its databases. A missing signature
// database is not an error (heuristics still work) but is reported by Info.
func New(cfg *config.Config) (*Scanner, error) {
	s := &Scanner{cfg: cfg}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	switch cfg.ClamAV.Enabled {
	case "on", "auto", "":
		s.clam = clamav.New(cfg.ClamAV.Socket, cfg.ClamAV.Timeout.Duration)
	}
	return s, nil
}

// Reload (re)loads the signature database and local lists from disk.
func (s *Scanner) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := sigdb.Open(DBPath(s.cfg))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("loading signature database: %w", err)
	}
	if old := s.db.Swap(db); old != nil {
		// Give in-flight lookups time to finish before unmapping.
		time.AfterFunc(2*time.Minute, old.Close)
	}
	custom, err := sigdb.LoadLocalList(CustomSigDir(s.cfg))
	if err != nil {
		return fmt.Errorf("loading custom signatures: %w", err)
	}
	s.custom.Store(custom)
	allow, err := sigdb.LoadLocalList(AllowlistDir(s.cfg))
	if err != nil {
		return fmt.Errorf("loading allowlist: %w", err)
	}
	s.allow.Store(allow)
	return nil
}

// ReloadIfChanged reloads when the database file on disk has changed.
func (s *Scanner) ReloadIfChanged() (bool, error) {
	fi, err := os.Stat(DBPath(s.cfg))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if cur := s.db.Load(); cur != nil && cur.ModTime().Equal(fi.ModTime()) {
		return false, nil
	}
	return true, s.Reload()
}

// Info describes the loaded engines.
type Info struct {
	SignatureCount   int       `json:"signature_count"`
	SignatureSources []string  `json:"signature_sources"`
	SignatureDBDate  time.Time `json:"signature_db_date,omitempty"`
	CustomSignatures int       `json:"custom_signatures"`
	Allowlisted      int       `json:"allowlisted"`
	Heuristics       bool      `json:"heuristics"`
	ClamAV           string    `json:"clamav"`
	ClamAVVersion    string    `json:"clamav_version,omitempty"`
}

func (s *Scanner) Info(ctx context.Context) Info {
	db := s.db.Load()
	in := Info{
		SignatureCount:   db.Count(),
		CustomSignatures: s.custom.Load().Len(),
		Allowlisted:      s.allow.Load().Len(),
		Heuristics:       s.cfg.Heuristics.Enabled,
		ClamAV:           "disabled",
	}
	if db != nil {
		in.SignatureSources = db.Sources
		in.SignatureDBDate = db.Created
	}
	if s.clam != nil {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if v, err := s.clam.Version(ctx); err == nil {
			in.ClamAV = s.clam.Addr()
			in.ClamAVVersion = v
		} else {
			in.ClamAV = "unreachable (" + s.clam.Addr() + ")"
		}
	} else if s.cfg.ClamAV.Enabled != "off" {
		in.ClamAV = "not found"
	}
	return in
}

// LookupHash checks a SHA-256 against all signature sources.
func (s *Scanner) LookupHash(h sigdb.Hash) (Detection, bool, bool) {
	if _, ok := s.allow.Load().Lookup(h); ok {
		return Detection{}, false, true
	}
	if name, ok := s.custom.Load().Lookup(h); ok {
		return Detection{Engine: EngineCustom, Name: name, Score: 100, Description: "matches a local custom signature"}, true, false
	}
	if src, ok := s.db.Load().Lookup(h); ok {
		return Detection{Engine: EngineSignature, Name: "Malware.SHA256." + src, Score: 100, Description: "file hash matches known malware (" + src + ")"}, true, false
	}
	return Detection{}, false, false
}

type scanState struct {
	budget     archive.Budget
	detections []Detection
	warnings   []string
	objects    int
	maxScore   int
	allowTop   bool
}

// ScanBytes scans in-memory content. name is used for display and for
// filename-based heuristics.
func (s *Scanner) ScanBytes(ctx context.Context, name string, data []byte) *Result {
	start := time.Now()
	sum := sha256.Sum256(data)
	res := &Result{
		File:   name,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		Type:   string(heuristics.Detect(data)),
	}
	st := &scanState{budget: archive.Budget{Bytes: s.cfg.Limits.MaxTotalExtract, Files: s.cfg.Limits.MaxArchiveFiles}}

	var wg sync.WaitGroup
	var clamDet *Detection
	var clamWarn string
	if s.clam != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clamDet, clamWarn = s.clamScan(ctx, name, bytes.NewReader(data))
		}()
	}

	s.scanObject(ctx, st, filepath.Base(name), "", data, sum, 0)
	wg.Wait()
	if clamDet != nil && !st.allowTop {
		st.detections = append(st.detections, *clamDet)
		st.maxScore = max(st.maxScore, clamDet.Score)
	}
	if clamWarn != "" {
		st.warnings = append(st.warnings, clamWarn)
	}
	s.finish(res, st, start)
	return res
}

func (s *Scanner) clamScan(ctx context.Context, name string, r io.Reader) (*Detection, string) {
	sig, found, err := s.clam.Scan(ctx, r)
	if err != nil {
		return nil, "clamav: " + err.Error()
	}
	if !found {
		return nil, ""
	}
	return &Detection{Engine: EngineClamAV, Name: sig, Object: filepath.Base(name), Score: 100, Description: "ClamAV signature match"}, ""
}

func (s *Scanner) finish(res *Result, st *scanState, start time.Time) {
	sort.SliceStable(st.detections, func(i, j int) bool { return st.detections[i].Score > st.detections[j].Score })
	res.Detections = st.detections
	if res.Detections == nil {
		res.Detections = []Detection{}
	}
	res.Warnings = st.warnings
	res.ObjectsScanned = st.objects
	res.Score = st.maxScore
	res.Allowlisted = st.allowTop
	res.Verdict = VerdictSafe
	if st.maxScore >= s.cfg.Heuristics.Threshold {
		res.Verdict = VerdictMalicious
	}
	res.DurationMS = float64(time.Since(start).Microseconds()) / 1000
}

func (s *Scanner) scanObject(ctx context.Context, st *scanState, name, parent string, data []byte, sum [32]byte, depth int) {
	objPath := name
	if parent != "" {
		objPath = parent + "!" + name
	}
	if err := ctx.Err(); err != nil {
		st.warnings = append(st.warnings, objPath+": scan aborted: "+err.Error())
		return
	}
	st.objects++

	det, hit, allowed := s.LookupHash(sum)
	if allowed {
		if depth == 0 {
			st.allowTop = true
		}
		return
	}
	var local []Detection
	add := func(d Detection) {
		d.Object = objPath
		local = append(local, d)
	}
	defer func() {
		score := 0
		for _, d := range local {
			score += d.Score
		}
		st.maxScore = max(st.maxScore, score)
		st.detections = append(st.detections, local...)
	}()

	if hit {
		add(det)
		return // known malware: no need to analyse further
	}

	ft := heuristics.Detect(data)
	var children []heuristics.Child
	if s.cfg.Heuristics.Enabled {
		var fs []heuristics.Finding
		fs, children = heuristics.Analyze(name, data, ft)
		for _, f := range fs {
			add(Detection{Engine: EngineHeuristic, Name: f.Name, Score: f.Score, Description: f.Description})
		}
	}

	recurse := func(childName string, childData []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.scanObject(ctx, st, childName, objPath, childData, sha256.Sum256(childData), depth+1)
		return nil
	}

	if ft.IsArchive() || len(children) > 0 {
		if depth >= s.cfg.Limits.MaxArchiveDepth {
			add(Detection{Engine: EngineArchive, Name: "Heuristic.Archive.TooDeep", Score: 50,
				Description: fmt.Sprintf("archive nesting exceeds %d levels (possible recursive bomb)", s.cfg.Limits.MaxArchiveDepth)})
			return
		}
	}
	if ft.IsArchive() {
		r := archive.Extract(ft, name, data, &st.budget, archive.Options{
			MaxEntrySize:              s.cfg.Limits.MaxFileSize,
			MaxCompressRatio:          s.cfg.Limits.MaxCompressRatio,
			BlockEncryptedExecutables: s.cfg.Heuristics.BlockEncryptedExecutables,
		}, recurse)
		for _, f := range r.Findings {
			add(Detection{Engine: EngineArchive, Name: f.Name, Score: f.Score, Description: f.Description})
		}
		for _, w := range r.Warnings {
			st.warnings = append(st.warnings, objPath+": "+w)
		}
	} else if s.clam == nil {
		switch ft {
		case heuristics.Type7z, heuristics.TypeRAR, heuristics.TypeCAB, heuristics.TypeISO:
			st.warnings = append(st.warnings, fmt.Sprintf("%s: %s container not unpacked (enable ClamAV for full coverage)", objPath, ft))
		}
	}
	for _, c := range children {
		_ = recurse(c.Name, c.Data)
	}
}

// ScanFile scans a file on disk. Files larger than limits.max_file_size are
// hash-checked and sent to ClamAV (if available) but not analysed in memory.
func (s *Scanner) ScanFile(ctx context.Context, path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() <= s.cfg.Limits.MaxFileSize {
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		r := s.ScanBytes(ctx, path, data)
		return r, nil
	}
	return s.scanLarge(ctx, path, f, fi.Size())
}

func (s *Scanner) scanLarge(ctx context.Context, path string, f *os.File, size int64) (*Result, error) {
	start := time.Now()
	h := sha256.New()
	head := make([]byte, 64*1024)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	h.Write(head)
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	res := &Result{File: path, Size: size, SHA256: hex.EncodeToString(sum[:]), Type: string(heuristics.Detect(head))}
	st := &scanState{}
	st.objects = 1
	st.warnings = append(st.warnings, fmt.Sprintf("file exceeds max_file_size (%d bytes); content analysis limited to hash lookup and ClamAV", s.cfg.Limits.MaxFileSize))
	det, hit, allowed := s.LookupHash(sum)
	st.allowTop = allowed
	if hit {
		det.Object = filepath.Base(path)
		st.detections = append(st.detections, det)
		st.maxScore = det.Score
	}
	if !hit && !allowed && s.clam != nil {
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			d, w := s.clamScan(ctx, path, f)
			if d != nil {
				st.detections = append(st.detections, *d)
				st.maxScore = max(st.maxScore, d.Score)
			}
			if w != "" {
				st.warnings = append(st.warnings, w)
			}
		}
	}
	s.finish(res, st, start)
	return res, nil
}
