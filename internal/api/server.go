// Package api implements FileGate's authenticated REST API.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/isaluki/filegate/internal/apikey"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
	"github.com/isaluki/filegate/internal/updater"
)

// Server is the HTTP API.
type Server struct {
	cfg      *config.Config
	scanner  *scanner.Scanner
	keys     *apikey.Verifier
	log      *slog.Logger
	sem      chan struct{}
	version  string
	started  time.Time
	updating chan struct{}
}

func New(cfg *config.Config, sc *scanner.Scanner, keys *apikey.Verifier, log *slog.Logger, version string) *Server {
	return &Server{
		cfg:      cfg,
		scanner:  sc,
		keys:     keys,
		log:      log,
		sem:      make(chan struct{}, cfg.API.MaxConcurrent),
		version:  version,
		started:  time.Now(),
		updating: make(chan struct{}, 1),
	}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.Handle("GET /v1/status", s.auth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("POST /v1/scan", s.auth(http.HandlerFunc(s.handleScan)))
	mux.Handle("GET /v1/hash/{hash}", s.auth(http.HandlerFunc(s.handleHash)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return s.logRequests(mux)
}

type ctxKey struct{}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := r.Header.Get("X-API-Key")
		if presented == "" {
			if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
				presented = strings.TrimSpace(h[7:])
			}
		}
		if presented == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="filegate"`)
			writeError(w, http.StatusUnauthorized, "missing API key (use 'Authorization: Bearer <key>' or 'X-API-Key')")
			return
		}
		k, ok := s.keys.Verify(presented)
		if !ok {
			s.log.Warn("rejected API key", "remote", s.remoteAddr(r), "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="filegate", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, k)))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic handling request", "panic", p, "path", r.URL.Path)
				writeError(rec, http.StatusInternalServerError, "internal error")
			}
			if r.URL.Path == "/v1/health" {
				return
			}
			s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"remote", s.remoteAddr(r), "duration_ms", time.Since(start).Milliseconds())
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(rec, r)
	})
}

func (s *Server) remoteAddr(r *http.Request) string {
	if s.cfg.API.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	rd := updater.Check(s.cfg, s.scanner.SignatureCount())
	if rd.NeedUpdate {
		go s.maybeUpdate(context.WithoutCancel(r.Context()), true)
	}
	resp := map[string]any{"status": "ok", "version": s.version}
	switch {
	case rd.Err != nil:
		resp["status"], resp["error"] = "not_ready", rd.Err.Error()
	case !rd.Ready:
		resp["status"], resp["error"] = "updating", rd.Reason
	default:
		if err := s.scanner.ClamAVReady(r.Context()); err != nil {
			resp["status"], resp["error"] = "not_ready", err.Error()
		}
	}
	code := http.StatusOK
	if resp["status"] != "ok" {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, resp)
}

// gate answers "retry" (and starts an update) when the signature database is
// missing or stale, or "error" if updating is currently failing. It reports
// whether the scan may proceed.
func (s *Server) gate(w http.ResponseWriter, r *http.Request) bool {
	rd := updater.Check(s.cfg, s.scanner.SignatureCount())
	if rd.Ready {
		return true
	}
	if rd.Err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"verdict": scanner.VerdictError, "error": rd.Err.Error()})
		return false
	}
	if rd.NeedUpdate {
		go s.maybeUpdate(context.WithoutCancel(r.Context()), true)
	}
	secs := int(updater.RetryAfter.Seconds())
	w.Header().Set("Retry-After", fmt.Sprint(secs))
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"verdict":             scanner.VerdictRetry,
		"reason":              rd.Reason,
		"retry_after_seconds": secs,
		"note":                "the signature database is being updated; resend this file shortly",
	})
	return false
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := updater.LoadState(s.cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        s.version,
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"engines":        s.scanner.Info(r.Context()),
		"updates": map[string]any{
			"last_update": st.LastUpdate,
			"last_full":   st.LastFull,
			"last_error":  st.LastError,
		},
		"limits": map[string]any{
			"max_upload_size":      s.cfg.API.MaxUploadSize,
			"max_concurrent_scans": s.cfg.API.MaxConcurrent,
		},
	})
}

func (s *Server) handleHash(w http.ResponseWriter, r *http.Request) {
	hs := strings.ToLower(r.PathValue("hash"))
	raw, err := hex.DecodeString(hs)
	if err != nil || (len(raw) != 32 && len(raw) != 16) {
		writeError(w, http.StatusBadRequest, "expected a hex SHA-256 (64 chars) or MD5 (32 chars)")
		return
	}
	var d scanner.Detection
	var hit, allowed bool
	if len(raw) == 32 {
		var h sigdb.Hash
		copy(h[:], raw)
		d, hit, allowed = s.scanner.LookupHash(h, nil)
	} else {
		var h sigdb.HashMD5
		copy(h[:], raw)
		d, hit, _ = s.scanner.LookupHash(sigdb.Hash{}, &h)
	}
	resp := map[string]any{"hash": hs, "known": hit}
	switch {
	case hit:
		resp["verdict"], resp["detection"] = scanner.VerdictMalicious, d
	case allowed:
		resp["verdict"], resp["allowlisted"] = scanner.VerdictSafe, true
	default:
		// Absence from hash lists says nothing about safety.
		resp["verdict"] = "unknown"
		resp["note"] = "hash not in the signature database; upload the file to /v1/scan for a verdict"
	}
	writeJSON(w, http.StatusOK, resp)
}

var errTooLarge = errors.New("upload too large")

// readUpload returns the uploaded file name, content and optional archive
// password from either a multipart form (fields "file" and "password") or a
// raw request body (password in the X-Archive-Password header). Passwords
// are deliberately not accepted in the URL, which ends up in access logs.
func (s *Server) readUpload(r *http.Request) (string, []byte, string, error) {
	limit := s.cfg.API.MaxUploadSize
	name := r.URL.Query().Get("filename")
	password := r.Header.Get("X-Archive-Password")
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "multipart/form-data" && params["boundary"] != "" {
		mr, err := r.MultipartReader()
		if err != nil {
			return "", nil, "", err
		}
		var data []byte
		found := false
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", nil, "", err
			}
			switch p.FormName() {
			case "file":
				if name == "" {
					name = p.FileName()
				}
				data, err = readLimited(p, limit)
				found = true
			case "password":
				var b []byte
				b, err = readLimited(p, 1024)
				password = string(b)
			}
			p.Close()
			if err != nil {
				return "", nil, "", err
			}
		}
		if !found {
			return "", nil, "", errors.New(`multipart body has no "file" field`)
		}
		return name, data, password, nil
	}
	if name == "" {
		if _, params, err := mime.ParseMediaType(r.Header.Get("Content-Disposition")); err == nil {
			name = params["filename"]
		}
	}
	data, err := readLimited(r.Body, limit)
	return name, data, password, err
}

func readLimited(rd io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(rd, limit+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errTooLarge
		}
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errTooLarge
	}
	return data, nil
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.gate(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.API.MaxUploadSize+1<<20)
	name, data, password, err := s.readUpload(r)
	if err != nil {
		if errors.Is(err, errTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload exceeds max_upload_size (%d bytes)", s.cfg.API.MaxUploadSize))
			return
		}
		writeError(w, http.StatusBadRequest, "reading upload: "+err.Error())
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty upload; send the file as the request body or as multipart field \"file\"")
		return
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "" || name == "." || name == "/" {
		name = "upload"
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-r.Context().Done():
		writeError(w, http.StatusServiceUnavailable, "request cancelled while waiting for a scan slot")
		return
	}
	res := s.scanner.ScanBytesWith(r.Context(), name, data, scanner.Options{Password: password})
	k, _ := r.Context().Value(ctxKey{}).(apikey.Key)
	s.log.Info("scan", "file", name, "size", len(data), "sha256", res.SHA256, "verdict", res.Verdict,
		"score", res.Score, "detections", len(res.Detections), "key", k.Name, "duration_ms", res.DurationMS)
	status := http.StatusOK
	if res.Failed() {
		// No trustworthy verdict: the body explains what could not be inspected.
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, res)
}

// Run serves until ctx is cancelled, reloading the signature database when
// it changes on disk and (optionally) running scheduled updates.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.API.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	go s.background(ctx)

	errc := make(chan error, 1)
	go func() {
		s.log.Info("FileGate API listening", "addr", s.cfg.API.Listen, "tls", s.cfg.API.TLSCert != "", "keys", s.keys.Count())
		if s.cfg.API.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(s.cfg.API.TLSCert, s.cfg.API.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	s.log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func (s *Server) background(ctx context.Context) {
	reload := time.NewTicker(max(s.cfg.API.DBReloadInterval.Duration, 5*time.Second))
	defer reload.Stop()
	var upd <-chan time.Time
	if s.cfg.API.AutoUpdate {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		upd = t.C
		go s.maybeUpdate(ctx, false)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if changed, err := s.scanner.ReloadIfChanged(); err != nil {
				s.log.Error("reloading signature database", "err", err)
			} else if changed {
				s.log.Info("signature database reloaded", "signatures", s.scanner.Info(ctx).SignatureCount)
			}
		case <-upd:
			go s.maybeUpdate(ctx, false)
		}
	}
}

func (s *Server) maybeUpdate(ctx context.Context, force bool) {
	select {
	case s.updating <- struct{}{}:
		defer func() { <-s.updating }()
	default:
		return
	}
	if !force && !updater.Due(s.cfg) {
		return
	}
	s.log.Info("running scheduled signature update")
	rep, err := updater.Run(ctx, s.cfg, updater.Options{})
	if err != nil {
		if errors.Is(err, updater.ErrLocked) {
			return
		}
		s.log.Error("signature update failed", "err", err)
		return
	}
	s.log.Info("signature update complete", "full", rep.Full, "hashes", rep.After, "duration_ms", rep.DurationMS)
	if rep.Changed {
		if err := s.scanner.Reload(); err != nil {
			s.log.Error("reloading signature database", "err", err)
		}
	}
}
