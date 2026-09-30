package updater

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/sigdb"
)

// RetryAfter is the delay suggested to clients while the database updates.
const RetryAfter = 60 * time.Second

// failureWindow is how long a failed update is reported as an error before
// another update is attempted.
const failureWindow = 10 * time.Minute

// Readiness is the result of checking the signature database before a scan.
type Readiness struct {
	// Ready means scans may proceed.
	Ready bool
	// NeedUpdate means the caller should start an update and answer "retry".
	NeedUpdate bool
	// Updating means an update is already running; answer "retry".
	Updating bool
	// Reason explains a non-ready state.
	Reason string
	// Err is set when no update can help right now (e.g. the last attempt
	// failed moments ago); the caller should answer "error".
	Err error
}

// LastRefresh is when the database was last confirmed current: the last
// successful update, or the database build time if no state is recorded.
func LastRefresh(cfg *config.Config) time.Time {
	t := LoadState(cfg).LastUpdate
	if set, err := sigdb.OpenSet(scanner.DBPath(cfg), scanner.DeltaPath(cfg)); err == nil {
		if c := set.Created(); c.After(t) {
			t = c
		}
		set.Close()
	}
	return t
}

// Updating reports whether another process holds the update lock.
// The probe opens the lock file read-only so it also works for users who
// cannot write the data directory.
func Updating(cfg *config.Config) bool {
	f, err := os.Open(filepath.Join(cfg.DataDir, ".update.lock"))
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return errors.Is(err, syscall.EWOULDBLOCK)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// Check decides whether a scan may proceed given the loaded signature count.
func Check(cfg *config.Config, signatures int) Readiness {
	if !cfg.Policy.RequireSignatures {
		return Readiness{Ready: true}
	}
	maxAge := cfg.Policy.MaxSignatureAge.Duration
	var reason string
	switch {
	case signatures == 0:
		reason = "signature database is not downloaded yet"
	case maxAge > 0 && time.Since(LastRefresh(cfg)) > maxAge:
		reason = fmt.Sprintf("signature database is older than %s", maxAge)
	default:
		return Readiness{Ready: true}
	}
	if Updating(cfg) {
		return Readiness{Updating: true, Reason: reason + "; an update is in progress"}
	}
	st := LoadState(cfg)
	if st.LastError != "" && st.LastAttempt.After(st.LastUpdate) && time.Since(st.LastAttempt) < failureWindow {
		return Readiness{Reason: reason, Err: fmt.Errorf("%s and the last update attempt failed: %s", reason, st.LastError)}
	}
	return Readiness{NeedUpdate: true, Reason: reason + "; an update has been started"}
}

// CanWrite reports whether this process can update the database.
func CanWrite(cfg *config.Config) bool {
	dir := cfg.DataDir
	for {
		if _, err := os.Stat(dir); err == nil {
			return syscall.Access(dir, 0x2 /* W_OK */) == nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// StartDetached launches `filegate update` in its own session so it keeps
// running after the calling CLI process exits. Output goes to
// <data_dir>/update.log.
func StartDetached(cfg *config.Config) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(cfg.DataDir, "update.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(self, "--config", cfg.Path(), "update")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
