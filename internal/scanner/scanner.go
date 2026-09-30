// Package scanner orchestrates FileGate's detection engines: the hash
// signature database (SHA-256 and MD5), local custom signatures, ClamAV,
// the heuristic engine and recursive archive unpacking.
package scanner

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// VerdictError means the content could not be fully inspected, so no
	// trustworthy safe/malicious verdict can be given.
	VerdictError = "error"
	// VerdictRetry means the signature database is being downloaded; the
	// caller should resend the file shortly. Produced by the CLI/API gate.
	VerdictRetry = "retry"

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
	MD5            string      `json:"md5,omitempty"`
	Type           string      `json:"type"`
	Verdict        string      `json:"verdict"`
	Error          string      `json:"error,omitempty"`
	Unscannable    []Issue     `json:"unscannable,omitempty"`
	Score          int         `json:"score"`
	Detections     []Detection `json:"detections"`
	ObjectsScanned int         `json:"objects_scanned"`
	Warnings       []string    `json:"warnings,omitempty"`
	Allowlisted    bool        `json:"allowlisted,omitempty"`
	DurationMS     float64     `json:"duration_ms"`
}

// Issue records content that could not be inspected.
type Issue struct {
	Object string `json:"object,omitempty"`
	Reason string `json:"reason"`
}

// Options are per-scan settings.
type Options struct {
	// Password decrypts password-protected archives. FileGate never guesses.
	Password string
}

// Malicious reports whether the verdict is malicious.
func (r *Result) Malicious() bool { return r.Verdict == VerdictMalicious }

// Failed reports whether the scan could not produce a trustworthy verdict.
func (r *Result) Failed() bool { return r.Verdict == VerdictError }

// ErrNoSignatures is returned by Ready when no signature database is loaded.
var ErrNoSignatures = errors.New("signature database not loaded; run 'filegate update' (or 'sudo filegate update')")

// ClamAVError explains why the required ClamAV engine is unusable.
type ClamAVError struct {
	Reason       string
	Instructions string
}

func (e *ClamAVError) Error() string {
	if e.Instructions == "" {
		return "ClamAV is required: " + e.Reason
	}
	return "ClamAV is required: " + e.Reason + "\n" + e.Instructions
}

// Scanner is safe for concurrent use.
type Scanner struct {
	cfg    *config.Config
	db     atomic.Pointer[sigdb.Set]
	custom atomic.Pointer[sigdb.LocalList]
	allow  atomic.Pointer[sigdb.LocalList]
	clam   atomic.Pointer[clamav.Client]
	mu     sync.Mutex // serialises reloads
}

// Paths within the data directory.
func DBPath(cfg *config.Config) string       { return filepath.Join(cfg.DataDir, "hashes.fgdb") }
func DeltaPath(cfg *config.Config) string    { return filepath.Join(cfg.DataDir, "hashes-delta.fgdb") }
func CustomSigDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "signatures") }
func AllowlistDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "allowlist") }
func UpdateStatePath(cfg *config.Config) string {
	return filepath.Join(cfg.DataDir, "update-state.json")
}

// New creates a scanner and loads its databases. A missing signature
// database is not an error here; Ready reports it.
func New(cfg *config.Config) (*Scanner, error) {
	s := &Scanner{cfg: cfg}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	s.clamClient()
	return s, nil
}

func (s *Scanner) clamRequired() bool {
	return s.cfg.ClamAV.Enabled == "required" || s.cfg.ClamAV.Enabled == "on" || s.cfg.ClamAV.Enabled == ""
}

// clamClient returns the clamd client, detecting the socket lazily so a
// clamd installed after FileGate started is picked up without a restart.
func (s *Scanner) clamClient() *clamav.Client {
	if s.cfg.ClamAV.Enabled == "off" {
		return nil
	}
	if c := s.clam.Load(); c != nil {
		return c
	}
	c := clamav.New(s.cfg.ClamAV.Socket, s.cfg.ClamAV.Timeout.Duration)
	if c != nil {
		s.clam.Store(c)
	}
	return c
}

// ClamAVReady checks that the required ClamAV engine is reachable.
func (s *Scanner) ClamAVReady(ctx context.Context) error {
	if !s.clamRequired() {
		return nil
	}
	c := s.clamClient()
	if c == nil {
		return &ClamAVError{Reason: "no clamd socket found", Instructions: clamav.InstallInstructions()}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		return clamUnreachable(c, err)
	}
	return nil
}

func clamUnreachable(c *clamav.Client, err error) error {
	reason := fmt.Sprintf("clamd at %s is not responding (%v)", c.Addr(), err)
	if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") {
		return &ClamAVError{Reason: fmt.Sprintf("permission denied connecting to clamd at %s; add this user to the clamd socket's group", c.Addr())}
	}
	return &ClamAVError{Reason: reason, Instructions: clamav.InstallInstructions()}
}

// Reload (re)loads the signature database and local lists from disk.
func (s *Scanner) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set, err := sigdb.OpenSet(DBPath(s.cfg), DeltaPath(s.cfg))
	if err != nil {
		return fmt.Errorf("loading signature database: %w", err)
	}
	if old := s.db.Swap(set); old != nil {
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

// SignatureCount returns the number of loaded feed hashes.
func (s *Scanner) SignatureCount() int { return s.db.Load().Count() }

// Ready reports whether a signature database is loaded.
func (s *Scanner) Ready() error {
	if s.cfg.Policy.RequireSignatures && s.SignatureCount() == 0 {
		return ErrNoSignatures
	}
	return nil
}

// ReloadIfChanged reloads when a database file on disk has changed.
func (s *Scanner) ReloadIfChanged() (bool, error) {
	var disk [2]time.Time
	for i, p := range []string{DBPath(s.cfg), DeltaPath(s.cfg)} {
		if fi, err := os.Stat(p); err == nil {
			disk[i] = fi.ModTime()
		}
	}
	cur := s.db.Load().ModTimes()
	if cur[0].Equal(disk[0]) && cur[1].Equal(disk[1]) {
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
	set := s.db.Load()
	in := Info{
		SignatureCount:   set.Count(),
		SignatureSources: set.Sources(),
		SignatureDBDate:  set.Created(),
		CustomSignatures: s.custom.Load().Len(),
		Allowlisted:      s.allow.Load().Len(),
		Heuristics:       s.cfg.Heuristics.Enabled,
		ClamAV:           "disabled",
	}
	if c := s.clamClient(); c != nil {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if v, err := c.Version(ctx); err == nil {
			in.ClamAV, in.ClamAVVersion = c.Addr(), v
		} else if c.Ping(ctx) == nil {
			in.ClamAV = c.Addr() // reachable; this clamd does not report its version
		} else {
			in.ClamAV = "unreachable (" + c.Addr() + ")"
		}
	} else if s.cfg.ClamAV.Enabled != "off" {
		in.ClamAV = "not found"
	}
	return in
}

// LookupHash checks an object's hashes against all signature sources. The
// allowlist only honours SHA-256: MD5 collisions are practical, so an MD5
// allowlist entry could be abused to whitelist crafted malware.
func (s *Scanner) LookupHash(h256 sigdb.Hash, hmd5 *sigdb.HashMD5) (Detection, bool, bool) {
	if _, ok := s.allow.Load().Lookup(h256); ok {
		return Detection{}, false, true
	}
	custom := s.custom.Load()
	if name, ok := custom.Lookup(h256); ok {
		return Detection{Engine: EngineCustom, Name: name, Score: 100, Description: "matches a local custom signature"}, true, false
	}
	set := s.db.Load()
	if src, ok := set.Lookup(h256); ok {
		return Detection{Engine: EngineSignature, Name: "Malware.SHA256." + src, Score: 100, Description: "SHA-256 matches known malware (" + src + ")"}, true, false
	}
	if hmd5 != nil {
		if name, ok := custom.LookupMD5(*hmd5); ok {
			return Detection{Engine: EngineCustom, Name: name, Score: 100, Description: "matches a local custom signature (MD5)"}, true, false
		}
		if src, ok := set.LookupMD5(*hmd5); ok {
			return Detection{Engine: EngineSignature, Name: "Malware.MD5." + src, Score: 100, Description: "MD5 matches known malware (" + src + ")"}, true, false
		}
	}
	return Detection{}, false, false
}

type scanState struct {
	budget      archive.Budget
	detections  []Detection
	warnings    []string
	objects     int
	maxScore    int
	allowTop    bool
	unscannable []Issue
	clamOK      func() bool // whether ClamAV successfully scanned the top-level file
	opts        Options
}

func (st *scanState) cannotScan(obj, reason string) {
	st.unscannable = append(st.unscannable, Issue{Object: obj, Reason: reason})
}

// clamScan runs ClamAV on r. It returns a detection, or an error message
// describing why ClamAV could not scan (empty on success).
func (s *Scanner) clamScan(ctx context.Context, obj string, r io.Reader) (*Detection, string) {
	c := s.clamClient()
	if c == nil {
		if s.clamRequired() {
			return nil, (&ClamAVError{Reason: "no clamd socket found", Instructions: clamav.InstallInstructions()}).Error()
		}
		return nil, ""
	}
	sig, found, err := c.Scan(ctx, r)
	switch {
	case errors.Is(err, clamav.ErrSizeLimit):
		return nil, "ClamAV rejected the file as too large; raise StreamMaxLength in clamd.conf (and MaxFileSize/MaxScanSize) above limits.max_file_size"
	case err != nil:
		return nil, clamUnreachable(c, err).Error()
	case found && strings.HasPrefix(sig, "Heuristics.Limits.Exceeded"):
		// AlertExceedsMax: ClamAV skipped part of the file due to its limits.
		return nil, "ClamAV could not scan all content (" + sig + "); raise MaxFileSize/MaxScanSize/MaxRecursion in clamd.conf"
	case found && strings.HasPrefix(sig, "Heuristics.Encrypted"):
		return nil, "ClamAV found encrypted content it cannot inspect (" + sig + ")"
	case found:
		return &Detection{Engine: EngineClamAV, Name: sig, Object: obj, Score: 100, Description: "ClamAV signature match"}, ""
	}
	return nil, ""
}

// handleClam records a ClamAV outcome for object obj.
func (s *Scanner) handleClam(st *scanState, obj string, det *Detection, errMsg string) {
	if det != nil {
		st.detections = append(st.detections, *det)
		st.maxScore = max(st.maxScore, det.Score)
	}
	if errMsg == "" {
		return
	}
	if s.clamRequired() {
		st.cannotScan(obj, errMsg)
	} else {
		st.warnings = append(st.warnings, obj+": clamav: "+errMsg)
	}
}

// ScanBytes scans in-memory content. name is used for display and for
// filename-based heuristics.
func (s *Scanner) ScanBytes(ctx context.Context, name string, data []byte) *Result {
	return s.ScanBytesWith(ctx, name, data, Options{})
}

// ScanBytesWith scans in-memory content with per-scan options.
func (s *Scanner) ScanBytesWith(ctx context.Context, name string, data []byte, opts Options) *Result {
	start := time.Now()
	sum := sha256.Sum256(data)
	msum := md5.Sum(data)
	res := &Result{
		File:   name,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		MD5:    hex.EncodeToString(msum[:]),
		Type:   string(heuristics.Detect(data)),
	}
	st := &scanState{budget: archive.Budget{Bytes: s.cfg.Limits.MaxTotalExtract, Files: s.cfg.Limits.MaxArchiveFiles}, opts: opts}
	top := filepath.Base(name)

	// ClamAV scans the whole file (recursing into archives itself) in
	// parallel with FileGate's own engines.
	var wg sync.WaitGroup
	var clamDet *Detection
	var clamErr string
	active := s.cfg.ClamAV.Enabled != "off"
	if active {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clamDet, clamErr = s.clamScan(ctx, top, bytes.NewReader(data))
		}()
	}
	st.clamOK = func() bool { wg.Wait(); return active && s.clamClient() != nil && clamErr == "" }

	s.scanObject(ctx, st, top, "", data, sum, msum, 0, false, nil)
	wg.Wait()
	if !st.allowTop && active {
		s.handleClam(st, top, clamDet, clamErr)
	}
	s.finish(res, st, start)
	return res
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
	if err := s.Ready(); err != nil && !st.allowTop {
		st.unscannable = append([]Issue{{Reason: err.Error()}}, st.unscannable...)
	}
	res.Unscannable = st.unscannable
	switch {
	case st.maxScore >= s.cfg.Heuristics.Threshold:
		// A positive detection is conclusive even if other parts were unscannable.
		res.Verdict = VerdictMalicious
	case st.allowTop:
		res.Verdict = VerdictSafe
	case len(st.unscannable) > 0 && s.cfg.Policy.Unscannable == "malicious":
		res.Verdict = VerdictMalicious
	case len(st.unscannable) > 0:
		res.Verdict = VerdictError
		// The first reason is the headline; every issue is listed in Unscannable.
		res.Error = st.unscannable[0].Reason
	default:
		res.Verdict = VerdictSafe
	}
	res.DurationMS = float64(time.Since(start).Microseconds()) / 1000
}

// scanObject analyses one object. clamThis requests a direct ClamAV scan
// (for content ClamAV cannot reach via the top-level file, such as members
// FileGate decrypted). clamCovered, when non-nil, says whether an ancestor's
// direct ClamAV scan succeeded; nil means coverage comes from the top-level scan.
func (s *Scanner) scanObject(ctx context.Context, st *scanState, name, parent string, data []byte, sum [32]byte, msum [16]byte, depth int, clamThis bool, clamCovered *bool) {
	objPath := name
	if parent != "" {
		objPath = parent + "!" + name
	}
	if err := ctx.Err(); err != nil {
		st.cannotScan(objPath, "scan aborted: "+err.Error())
		return
	}
	st.objects++

	// An empty object cannot be malicious, and the empty-file hash appears in
	// several feeds (malware URLs sometimes serve empty responses).
	var det Detection
	var hit, allowed bool
	if len(data) > 0 {
		det, hit, allowed = s.LookupHash(sum, &msum)
	}
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

	// Content ClamAV cannot reach through the top-level file (e.g. members
	// FileGate decrypted with a known password) is sent to ClamAV directly.
	if clamThis {
		ok := false
		if s.cfg.ClamAV.Enabled != "off" {
			d, e := s.clamScan(ctx, objPath, bytes.NewReader(data))
			if d != nil {
				add(*d)
			}
			if e != "" {
				s.handleClam(st, objPath, nil, e)
			}
			ok = e == "" && s.clamClient() != nil
		}
		clamCovered = &ok
	}
	covered := func() bool {
		if clamCovered != nil {
			return *clamCovered
		}
		return st.clamOK != nil && st.clamOK()
	}

	ft := heuristics.Detect(data)
	if heuristics.IsEncryptedOffice(data) {
		st.cannotScan(objPath, "password-protected Office document; content cannot be inspected")
	}
	var children []heuristics.Child
	if s.cfg.Heuristics.Enabled {
		var fs []heuristics.Finding
		fs, children = heuristics.Analyze(name, data, ft)
		for _, f := range fs {
			add(Detection{Engine: EngineHeuristic, Name: f.Name, Score: f.Score, Description: f.Description})
		}
	}

	recurse := func(childName string, childData []byte, decrypted bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.scanObject(ctx, st, childName, objPath, childData, sha256.Sum256(childData), md5.Sum(childData), depth+1, decrypted, clamCovered)
		return nil
	}

	if ft.IsArchive() || len(children) > 0 {
		if depth >= s.cfg.Limits.MaxArchiveDepth {
			add(Detection{Engine: EngineArchive, Name: "Heuristic.Archive.TooDeep", Score: 50,
				Description: fmt.Sprintf("archive nesting exceeds %d levels (possible recursive bomb)", s.cfg.Limits.MaxArchiveDepth)})
			st.cannotScan(objPath, fmt.Sprintf("nested deeper than max_archive_depth (%d)", s.cfg.Limits.MaxArchiveDepth))
			return
		}
	}
	if ft.IsArchive() {
		r := archive.Extract(ft, name, data, &st.budget, archive.Options{
			MaxEntrySize:     s.cfg.Limits.MaxFileSize,
			MaxCompressRatio: s.cfg.Limits.MaxCompressRatio,
			Password:         st.opts.Password,
		}, recurse)
		for _, f := range r.Findings {
			add(Detection{Engine: EngineArchive, Name: f.Name, Score: f.Score, Description: f.Description})
		}
		for _, w := range r.Warnings {
			st.warnings = append(st.warnings, objPath+": "+w)
		}
		for _, u := range r.Unscannable {
			st.cannotScan(objPath, u)
		}
	} else {
		switch ft {
		case heuristics.Type7z, heuristics.TypeRAR, heuristics.TypeCAB, heuristics.TypeISO:
			// Only ClamAV unpacks these (it recurses into archives itself).
			if !covered() {
				st.cannotScan(objPath, fmt.Sprintf("%s containers can only be inspected with ClamAV, which did not scan it", ft))
			}
		}
	}
	for _, c := range children {
		_ = recurse(c.Name, c.Data, false)
	}
}

// ScanFile scans a file on disk. Files larger than limits.max_file_size are
// hash-checked and streamed to ClamAV but not analysed in memory.
func (s *Scanner) ScanFile(ctx context.Context, path string) (*Result, error) {
	return s.ScanFileWith(ctx, path, Options{})
}

// ScanFileWith scans a file on disk with per-scan options.
func (s *Scanner) ScanFileWith(ctx context.Context, path string, opts Options) (*Result, error) {
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
		return s.ScanBytesWith(ctx, path, data, opts), nil
	}
	return s.scanLarge(ctx, path, f, fi.Size())
}

func (s *Scanner) scanLarge(ctx context.Context, path string, f *os.File, size int64) (*Result, error) {
	start := time.Now()
	h, hm := sha256.New(), md5.New()
	head := make([]byte, 64*1024)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	w := io.MultiWriter(h, hm)
	w.Write(head)
	if _, err := io.Copy(w, f); err != nil {
		return nil, err
	}
	var sum [32]byte
	var msum [16]byte
	copy(sum[:], h.Sum(nil))
	copy(msum[:], hm.Sum(nil))
	res := &Result{File: path, Size: size, SHA256: hex.EncodeToString(sum[:]), MD5: hex.EncodeToString(msum[:]), Type: string(heuristics.Detect(head))}
	st := &scanState{objects: 1}
	obj := filepath.Base(path)
	det, hit, allowed := s.LookupHash(sum, &msum)
	st.allowTop = allowed
	if hit {
		det.Object = obj
		st.detections = append(st.detections, det)
		st.maxScore = det.Score
	}
	if !hit && !allowed {
		// Too large to analyse in memory: ClamAV is the only content engine.
		clamErr := "ClamAV is disabled"
		var d *Detection
		if s.cfg.ClamAV.Enabled != "off" {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			d, clamErr = s.clamScan(ctx, obj, f)
			if clamErr == "" && s.clamClient() == nil {
				clamErr = "ClamAV is not available"
			}
		}
		if d != nil {
			st.detections = append(st.detections, *d)
			st.maxScore = max(st.maxScore, d.Score)
		}
		if clamErr != "" {
			st.cannotScan(obj, fmt.Sprintf("file exceeds max_file_size (%d bytes) so only ClamAV can inspect it, but: %s", s.cfg.Limits.MaxFileSize, clamErr))
		}
	}
	s.finish(res, st, start)
	return res, nil
}
