package clamav

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallInstructions(t *testing.T) {
	cases := map[string]string{
		"ID=debian\n":                                  "sudo apt install clamav-daemon",
		"ID=ubuntu\nID_LIKE=debian\n":                  "sudo apt install clamav-daemon",
		"ID=linuxmint\nID_LIKE=\"ubuntu debian\"":      "sudo apt install clamav-daemon",
		"ID=fedora\n":                                  "sudo dnf install clamav clamd clamav-update",
		"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"": "sudo dnf install",
		"ID=arch\n":                                    "ClamAV (clamd) is required to proceed",
	}
	for osr, want := range cases {
		p := filepath.Join(t.TempDir(), "os-release")
		os.WriteFile(p, []byte(osr), 0o644)
		if got := installInstructions(p); !strings.Contains(got, want) {
			t.Errorf("%q: got %q, want it to contain %q", osr, got, want)
		}
	}
	if got := installInstructions("/nonexistent"); !strings.Contains(got, "required to proceed") {
		t.Errorf("missing os-release: %q", got)
	}
}
