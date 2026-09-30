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
	mux.Handle("GET /v1/hash/{sha256}", s.auth(http.HandlerFunc(s.handleHash)))
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
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.version})
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
	hs := strings.ToLower(r.PathValue("sha256"))
	var h sigdb.Hash
	if len(hs) != 64 {
		writeError(w, http.StatusBadRequest, "expected a 64-character hex SHA-256")
		return
	}
	if _, err := hex.Decode(h[:], []byte(hs)); err != nil {
		writeError(w, http.StatusBadRequest, "expected a 64-character hex SHA-256")
		return
	}
	d, hit, allowed := s.scanner.LookupHash(h)
	resp := map[string]any{"sha256": hs, "known": hit, "verdict": scanner.VerdictSafe, "allowlisted": allowed}
	if hit {
		resp["verdict"] = scanner.VerdictMalicious
		resp["detection"] = d
	} else {
		resp["note"] = "hash not in signature database; upload the file to /v1/scan for full analysis"
	}
	writeJSON(w, http.StatusOK, resp)
}

var errTooLarge = errors.New("upload too large")

// readUpload returns the uploaded file name and content from either a
// multipart form (field "file") or a raw request body.
func (s *Server) readUpload(r *http.Request) (string, []byte, error) {
	limit := s.cfg.API.MaxUploadSize
	name := r.URL.Query().Get("filename")
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "multipart/form-data" && params["boundary"] != "" {
		mr, err := r.MultipartReader()
		if err != nil {
			return "", nil, err
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return "", nil, errors.New(`multipart body has no "file" field`)
			}
			if err != nil {
				return "", nil, err
			}
			if p.FormName() != "file" {
				p.Close()
				continue
			}
			if name == "" {
				name = p.FileName()
			}
			data, err := readLimited(p, limit)
			p.Close()
			return name, data, err
		}
	}
	if name == "" {
		if _, params, err := mime.ParseMediaType(r.Header.Get("Content-Disposition")); err == nil {
			name = params["filename"]
		}
	}
	data, err := readLimited(r.Body, limit)
	return name, data, err
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
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.API.MaxUploadSize+1<<20)
	name, data, err := s.readUpload(r)
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
	res := s.scanner.ScanBytes(r.Context(), name, data)
	k, _ := r.Context().Value(ctxKey{}).(apikey.Key)
	s.log.Info("scan", "file", name, "size", len(data), "sha256", res.SHA256, "verdict", res.Verdict,
		"score", res.Score, "detections", len(res.Detections), "key", k.Name, "duration_ms", res.DurationMS)
	writeJSON(w, http.StatusOK, res)
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
		go s.maybeUpdate(ctx)
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
			go s.maybeUpdate(ctx)
		}
	}
}

func (s *Server) maybeUpdate(ctx context.Context) {
	select {
	case s.updating <- struct{}{}:
		defer func() { <-s.updating }()
	default:
		return
	}
	if !updater.Due(s.cfg) {
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
