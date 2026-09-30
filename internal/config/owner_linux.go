package config

import (
	"os"
	"path/filepath"
	"syscall"
)

// MatchDirOwner chowns path to the owner/group of its parent directory when
// running as root, so files written by `sudo filegate ...` stay readable by
// the unprivileged service user.
func MatchDirOwner(path string) {
	if os.Geteuid() != 0 {
		return
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
