#!/bin/sh
# Build (if needed) and install FileGate with its systemd units.
#
#   sudo ./scripts/install.sh            # CLI + hourly signature updates
#   sudo ./scripts/install.sh --api      # ...plus the REST API service
#   sudo ./scripts/install.sh --api --listen 0.0.0.0:8750
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "run as root (sudo $0 $*)" >&2
	exit 1
fi

cd "$(dirname "$0")/.."
if [ ! -x bin/filegate ]; then
	if ! command -v go >/dev/null 2>&1; then
		echo "Go toolchain not found; install Go 1.24+ or place a prebuilt binary at bin/filegate" >&2
		exit 1
	fi
	make build
fi

./bin/filegate service install "$@"

echo
echo "Check status with:   filegate status"
echo "Scan a file with:    filegate scan /path/to/file"
