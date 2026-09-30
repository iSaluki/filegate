package clamav

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// osRelease returns ID and ID_LIKE from /etc/os-release.
func osRelease(path string) (id string, like []string) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.ToLower(strings.Trim(v, `"'`))
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			like = strings.Fields(v)
		}
	}
	return id, like
}

func distroFamily(path string) string {
	id, like := osRelease(path)
	for _, d := range append([]string{id}, like...) {
		switch d {
		case "debian", "ubuntu":
			return "debian"
		case "fedora", "rhel", "centos":
			return "fedora"
		}
	}
	return ""
}

// limitsCmd replaces (or adds) clamd's size limits and AlertExceedsMax.
func limitsCmd(conf string) string {
	return fmt.Sprintf(`sudo sed -i -E '/^(StreamMaxLength|MaxFileSize|MaxScanSize|AlertExceedsMax) /d' %[1]s && `+
		`printf 'StreamMaxLength 256M\nMaxFileSize 256M\nMaxScanSize 1024M\nAlertExceedsMax yes\n' | sudo tee -a %[1]s >/dev/null`, conf)
}

// InstallInstructions explains how to install and start clamd on this host.
func InstallInstructions() string { return installInstructions("/etc/os-release") }

func installInstructions(osReleasePath string) string {
	switch distroFamily(osReleasePath) {
	case "debian":
		return "Install and start ClamAV (Debian/Ubuntu):\n" +
			"  sudo apt install clamav-daemon clamav-freshclam\n" +
			"  sudo systemctl enable --now clamav-freshclam clamav-daemon\n" +
			"Then raise clamd's limits so large files are fully scanned, and make it report anything it skips:\n" +
			"  " + limitsCmd("/etc/clamav/clamd.conf") + "\n" +
			"  sudo systemctl restart clamav-daemon\n" +
			"clamd becomes ready once freshclam has downloaded its databases (a few minutes on first install)."
	case "fedora":
		return "Install and start ClamAV (Fedora/RHEL):\n" +
			"  sudo dnf install clamav clamd clamav-update\n" +
			"  sudo sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamd.d/scan.conf\n" +
			"  " + limitsCmd("/etc/clamd.d/scan.conf") + "\n" +
			"  sudo freshclam\n" +
			"  sudo systemctl enable --now clamav-freshclam clamd@scan\n" +
			"  sudo usermod -aG virusgroup $USER   # so non-root users can reach the clamd socket (log in again afterwards)"
	default:
		return "ClamAV (clamd) is required to proceed. Install ClamAV with your distribution's package manager, " +
			"start clamd with freshclam enabled, set StreamMaxLength/MaxFileSize to at least FileGate's limits.max_file_size and " +
			"AlertExceedsMax to yes in clamd's config, and set clamav.socket in the FileGate config if its socket is not auto-detected."
	}
}
