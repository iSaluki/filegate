// Package service installs FileGate as systemd units.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/isaluki/filegate/internal/config"
)

const (
	ServiceUser = "filegate"
	BinaryPath  = "/usr/local/bin/filegate"
	UnitDir     = "/etc/systemd/system"
	APIUnit     = "filegate.service"
	UpdateUnit  = "filegate-update.service"
	UpdateTimer = "filegate-update.timer"
)

var apiUnitTmpl = template.Must(template.New("api").Parse(`[Unit]
Description=FileGate malware scanning REST API
Documentation=https://github.com/isaluki/filegate
After=network-online.target clamav-daemon.service
Wants=network-online.target

[Service]
Type=simple
User={{.User}}
Group={{.User}}
SupplementaryGroups={{.ExtraGroups}}
ExecStart={{.Binary}} --config {{.Config}} serve
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={{.DataDir}}
ReadOnlyPaths={{.ConfigDir}}

[Install]
WantedBy=multi-user.target
`))

var updateUnitTmpl = template.Must(template.New("update").Parse(`[Unit]
Description=FileGate signature database update
Documentation=https://github.com/isaluki/filegate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User={{.User}}
Group={{.User}}
ExecStart={{.Binary}} --config {{.Config}} update --quiet
Nice=10
IOSchedulingClass=idle
# The first run downloads every feed (VirusShare alone is ~500 files).
TimeoutStartSec=3h

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={{.DataDir}}
ReadOnlyPaths={{.ConfigDir}}
`))

var updateTimerTmpl = template.Must(template.New("timer").Parse(`[Unit]
Description=Periodic FileGate signature database update

[Timer]
OnBootSec=2min
OnUnitActiveSec={{.Interval}}
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
`))

type unitData struct {
	User, Binary, Config, ConfigDir, DataDir, Interval, ExtraGroups string
}

// Options for Install.
type Options struct {
	EnableAPI bool
	Listen    string
	Out       io.Writer
}

func run(out io.Writer, name string, args ...string) error {
	fmt.Fprintf(out, "+ %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command must be run as root (try sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not found; FileGate services require systemd")
	}
	return nil
}

func ensureUser(out io.Writer) (int, int, error) {
	u, err := user.Lookup(ServiceUser)
	if err != nil {
		nologin := "/usr/sbin/nologin"
		if _, err := os.Stat(nologin); err != nil {
			nologin = "/sbin/nologin"
		}
		if err := run(out, "useradd", "--system", "--no-create-home", "--home-dir", config.SystemDataDir,
			"--shell", nologin, "--user-group", ServiceUser); err != nil {
			return 0, 0, fmt.Errorf("creating user %s: %w", ServiceUser, err)
		}
		if u, err = user.Lookup(ServiceUser); err != nil {
			return 0, 0, err
		}
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func installBinary(out io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	if self == BinaryPath {
		return nil
	}
	src, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "installing %s -> %s\n", self, BinaryPath)
	return config.WriteFileAtomic(BinaryPath, src, 0o755)
}

// clamGroups returns extra groups so the service can reach clamd's socket.
func clamGroups() string {
	var gs []string
	for _, g := range []string{"clamav", "clamscan", "virusgroup"} {
		if _, err := user.LookupGroup(g); err == nil {
			gs = append(gs, g)
		}
	}
	return strings.Join(gs, " ")
}

// Install sets up the service user, directories, config and systemd units.
func Install(cfg *config.Config, opt Options) error {
	out := opt.Out
	if err := requireRoot(); err != nil {
		return err
	}
	if err := installBinary(out); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}
	uid, gid, err := ensureUser(out)
	if err != nil {
		return err
	}

	cfgPath := filepath.Join(config.SystemConfigDir, config.ConfigFileName)
	if cfg.Path() != cfgPath {
		fmt.Fprintf(out, "note: services use the system config %s\n", cfgPath)
	}
	if err := os.MkdirAll(config.SystemConfigDir, 0o755); err != nil {
		return err
	}
	_ = os.Chown(config.SystemConfigDir, 0, gid)
	_ = os.Chmod(config.SystemConfigDir, 0o755) // keys.json itself is 0640

	sys, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if sys.DataDir == "" {
		sys.DataDir = config.SystemDataDir
	}
	if opt.Listen != "" {
		sys.API.Listen = opt.Listen
	}
	sys.API.AutoUpdate = false // the systemd timer owns updates
	if _, err := os.Stat(cfgPath); err != nil || opt.Listen != "" {
		fmt.Fprintf(out, "writing %s\n", cfgPath)
		if err := sys.Save(); err != nil {
			return err
		}
	}
	for _, d := range []string{sys.DataDir, filepath.Join(sys.DataDir, "signatures"), filepath.Join(sys.DataDir, "allowlist")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		_ = os.Chown(d, uid, gid)
	}

	d := unitData{
		User: ServiceUser, Binary: BinaryPath, Config: cfgPath, ConfigDir: config.SystemConfigDir,
		DataDir: sys.DataDir, Interval: systemdDuration(sys.UpdateInterval.Duration), ExtraGroups: clamGroups(),
	}
	units := map[string]*template.Template{UpdateUnit: updateUnitTmpl, UpdateTimer: updateTimerTmpl}
	if opt.EnableAPI {
		units[APIUnit] = apiUnitTmpl
	}
	for name, t := range units {
		var buf bytes.Buffer
		if err := t.Execute(&buf, d); err != nil {
			return err
		}
		p := filepath.Join(UnitDir, name)
		fmt.Fprintf(out, "writing %s\n", p)
		if err := config.WriteFileAtomic(p, buf.Bytes(), 0o644); err != nil {
			return err
		}
	}
	if err := run(out, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run(out, "systemctl", "enable", "--now", UpdateTimer); err != nil {
		return err
	}
	// Populate the database immediately in the background.
	_ = run(out, "systemctl", "start", "--no-block", UpdateUnit)
	if opt.EnableAPI {
		if err := run(out, "systemctl", "enable", "--now", APIUnit); err != nil {
			return err
		}
	}
	return nil
}

// Uninstall stops and removes the units. Config, keys and data are kept.
func Uninstall(out io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	for _, u := range []string{APIUnit, UpdateTimer, UpdateUnit} {
		p := filepath.Join(UnitDir, u)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = run(out, "systemctl", "disable", "--now", u)
		if err := os.Remove(p); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed %s\n", p)
	}
	_ = run(out, "systemctl", "daemon-reload")
	fmt.Fprintf(out, "config (%s) and data (%s) were left in place\n", config.SystemConfigDir, config.SystemDataDir)
	return nil
}

// Status shows systemctl status for the units.
func Status(out io.Writer) error {
	cmd := exec.Command("systemctl", "--no-pager", "status", APIUnit, UpdateTimer, UpdateUnit)
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil // non-zero when a unit is inactive; output already shown
	}
	return err
}

func systemdDuration(d time.Duration) string {
	if d <= 0 {
		d = time.Hour
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
