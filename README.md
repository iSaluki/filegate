# FileGate

FileGate is a malware scanner for Linux. You give it a file or an archive and it returns a verdict, usually within milliseconds. It works as a CLI, and it can also run an optional REST API as a hardened systemd service. The API uses API keys that you create with the CLI.

FileGate never answers `safe` unless it could actually inspect everything. The possible verdicts are:

| Verdict | Meaning | CLI exit | HTTP |
|---|---|---|---|
| `safe` | Every object was inspected by every engine, and nothing was found. | 0 | 200 |
| `malicious` | At least one engine positively detected malware. | 1 | 200 |
| `error` | Some content could not be inspected, so no trustworthy verdict is possible. The `error` field says why. Common reasons: a password-protected archive with no valid password, clamd unavailable, a file over the size limits, a 7z/RAR archive that ClamAV could not open. Never treat this as safe. | 2 | 422 (503 if an engine is down) |
| `retry` | The signature database is missing or out of date. FileGate has started downloading it, so resend the file shortly. | 3 | 503 + `Retry-After` |

```
$ filegate scan invoice.zip
invoice.zip: MALICIOUS (Heuristic.Macro.PowerShell, Heuristic.Macro.Shell, Heuristic.Macro.Download)
    [ 40] heuristic Heuristic.Macro.PowerShell  in invoice.zip!invoice.docm!word/vbaProject.bin
    ...
$ filegate scan samples.zip
samples.zip: ERROR Archive is password protected and no valid password was specified
$ filegate scan --password infected samples.zip
samples.zip: MALICIOUS (Malware.SHA256.malwarebazaar-full)
```

## Detection engines

| Engine | What it does |
|---|---|
| **ClamAV** (required) | Every file is streamed to `clamd` alongside FileGate's own engines. This adds ClamAV's millions of maintained signatures (byte patterns, logical and bytecode signatures, PE section hashes) and its unpackers for 7z, RAR, CAB, ISO and more. FileGate finds the socket automatically. If clamd is missing or not responding, scans return `error` with install instructions for your distro. |
| **Hash signature DB** | Checks the SHA-256 **and** MD5 of every object, including each file inside an archive, against about 6M known-malware hashes: [MalwareBazaar](https://bazaar.abuse.ch), [ThreatFox](https://threatfox.abuse.ch) and [URLhaus](https://urlhaus.abuse.ch) payloads. [VirusShare](https://virusshare.com) (~33M MD5s) can be enabled too; see [Signature feeds](#signature-feeds). The database is memory-mapped and binary-searched, so it loads instantly. |
| **Heuristics** | Static analysis covering: <br>• **PE**: packers, W+X sections, encrypted code, injection/hollowing/keylogger import sets <br>• **ELF**: packers, IoT-botnet and miner strings <br>• **Office VBA**: a full MS-OVBA decompressor recovers macro source for analysis <br>• **Other Office**: XLM macros, Follina, template/OLE injection <br>• **RTF**: Equation Editor exploits <br>• **PDF**: auto-run JavaScript, `/Launch`; Flate streams are inflated <br>• **LNK**: shortcuts that launch interpreters <br>• **Scripts** (PowerShell, JS/VBS/HTA, shell, Python, PHP): cradles, AMSI bypass, reverse shells, web shells, ransomware commands <br>• **File names**: disguised names (double extensions, RTL override) |
| **Archives** | Unpacks zip (including OOXML/JAR/APK), tar, gzip, bzip2 and xz recursively. Detects zip/gzip bombs and recursive archives. Password-protected zips (ZipCrypto and WinZip AES) are decrypted only with a password you supply; FileGate never guesses. Decrypted members are also sent to ClamAV, because ClamAV cannot open encrypted archives itself. |
| **Custom / allowlist** | Your own SHA-256 or MD5 signatures go in `<data_dir>/signatures/*.txt`. Known-good files go in `<data_dir>/allowlist/*.txt`. The allowlist accepts **SHA-256 only**, because MD5 collisions are practical and could be abused to allowlist malware. |

### Scoring and accuracy

Each finding has a score, and scores are added up per object. Hash and ClamAV matches score 100, which is conclusive on its own. Weaker heuristic signals have to combine to reach the threshold (default 100).

The test corpus was 22,919 benign files (`/usr/bin`, `/usr/lib`, `/usr/share`, `/etc` and the Go tree), scanned with all default engines, including real ClamAV and the full feed database. All of them came back `safe`: 0 false positives and 0 errors. The median scan took 10 ms and the 99th percentile 84 ms. Most of that time is clamd.

## Install

Requires Linux with systemd and ClamAV. Building from source needs Go 1.24+.

**1. Install ClamAV.** The first time `filegate scan` finds no clamd, it prints these commands for your distro.

Debian / Ubuntu:

```sh
sudo apt install clamav-daemon clamav-freshclam
sudo systemctl enable --now clamav-freshclam clamav-daemon
# Let clamd scan large files fully, and report anything it has to skip:
sudo sed -i -E '/^(StreamMaxLength|MaxFileSize|MaxScanSize|AlertExceedsMax) /d' /etc/clamav/clamd.conf && \
  printf 'StreamMaxLength 256M\nMaxFileSize 256M\nMaxScanSize 1024M\nAlertExceedsMax yes\n' | sudo tee -a /etc/clamav/clamd.conf
sudo systemctl restart clamav-daemon
```

Fedora / RHEL:

```sh
sudo dnf install clamav clamd clamav-update
sudo sed -i 's/^#LocalSocket /LocalSocket /' /etc/clamd.d/scan.conf
sudo sed -i -E '/^(StreamMaxLength|MaxFileSize|MaxScanSize|AlertExceedsMax) /d' /etc/clamd.d/scan.conf && \
  printf 'StreamMaxLength 256M\nMaxFileSize 256M\nMaxScanSize 1024M\nAlertExceedsMax yes\n' | sudo tee -a /etc/clamd.d/scan.conf
sudo freshclam
sudo systemctl enable --now clamav-freshclam clamd@scan
```

On other distros, install ClamAV with your package manager, start clamd with freshclam enabled, and apply the same four clamd settings. FileGate requires ClamAV to proceed.

Why the clamd limits matter: clamd's defaults (25 MB) reject larger streams, which FileGate reports as `error`. With `AlertExceedsMax`, clamd reports content it skipped instead of silently answering OK. FileGate turns that report into `error`, never `safe`.

**2. Install FileGate.**

```sh
make build
sudo ./scripts/install.sh           # CLI + hourly signature updates (systemd timer)
sudo ./scripts/install.sh --api     # ...and the REST API service
```

`filegate service install` does the following:

1. Copies the binary to `/usr/local/bin`.
2. Creates an unprivileged `filegate` user, adding it to ClamAV's socket group.
3. Writes `/etc/filegate/config.json` and creates `/var/lib/filegate`.
4. Installs `filegate-update.timer`, plus the hardened `filegate.service` when you pass `--api`.

The first signature download starts immediately and takes a couple of minutes. Scans made before it finishes return `retry`.

## CLI

```
filegate scan <file|dir|->...   Scan files, directories (recursive) or stdin
    --password PW   password for password-protected archives
    --json          one JSON result per line
    --quiet         only print malicious files
    -v              show every finding, uninspectable content, hashes, timing
    --jobs N        parallel scans (default: #CPUs)
filegate update [--full] [--quiet] [--json]
filegate status [--json]
filegate serve [--listen ADDR] [--auto-update]
filegate apikey create --name NAME [--ttl 720h] | list | revoke <id|name>
filegate service install [--api] [--listen ADDR] | uninstall | status
filegate config show | init
```

```sh
filegate scan --quiet "$UPLOAD"
case $? in
  0) accept ;;
  1) quarantine ;;
  3) sleep 60; retry ;;       # database downloading
  *) hold_for_review ;;       # could not be fully inspected
esac
```

Any user can scan with the system database in `/var/lib/filegate`. If the database is missing or stale, `scan` starts a background update and exits with code 3 (`retry`). If the current user isn't allowed to update the database, it exits with code 2 and asks you to run `sudo filegate update`.

## REST API

```sh
sudo filegate apikey create --name webapp      # prints the key once; only its hash is stored
```

Send the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. Created and revoked keys take effect within seconds, with no restart.

| Method & path | Auth | Description |
|---|---|---|
| `POST /v1/scan` | ✔ | Scan an upload: a raw body (optional `?filename=`) or a multipart form field `file`. To scan a password-protected archive, send the password as the multipart field `password` or the `X-Archive-Password` header. Passwords are not accepted in the URL, because URLs end up in logs. |
| `GET /v1/hash/{sha256-or-md5}` | ✔ | Hash lookup. Returns `malicious` for a known hash, otherwise `unknown`. Absence from the lists is not evidence of safety. |
| `GET /v1/status` | ✔ | Engine and database status. |
| `GET /v1/health` | – | `200` when ready. Returns `503` while the database updates or if clamd is down. |

```sh
curl -H "Authorization: Bearer $KEY" -F file=@samples.zip -F password=infected http://127.0.0.1:8750/v1/scan
```

```json
{
  "file": "samples.zip",
  "verdict": "error",
  "error": "Archive is password protected and no valid password was specified",
  "unscannable": [{ "object": "samples.zip", "reason": "Archive is password protected and no valid password was specified" }],
  "detections": [], "sha256": "…", "md5": "…", "objects_scanned": 1, "duration_ms": 3.1
}
```

While the database is downloading, scans get `503` with a `Retry-After` header:

```json
{ "verdict": "retry", "reason": "signature database is not downloaded yet; an update is in progress", "retry_after_seconds": 60 }
```

## Signature feeds

| Feed | Hashes | Refresh |
|---|---|---|
| `malwarebazaar-full` / `-recent` | ~1.15M SHA-256 | full weekly + hourly |
| `threatfox-full` / `-recent` | SHA-256 | full weekly + hourly |
| `urlhaus-payloads` | ~4.8M SHA-256 | full weekly |
| `virusshare` (**disabled by default**) | ~33M MD5 | append-only shards |

VirusShare indexes everything submitted to it, including benign files. In testing it matched ordinary OS files (vim syntax files, a PostgreSQL SQL script), so it is off by default. Enable it with `"enabled": true` if you accept that trade-off. The first run downloads about 500 shards; after that only new shards are fetched.

How the database is stored and updated:

- **Base plus delta.** It is split into a base file, rebuilt on the weekly full refresh, and a small delta file. Hourly updates rewrite only the delta.
- **Per-source replacement.** A full refresh replaces each re-downloaded feed's entries. It keeps entries from feeds that weren't re-downloaded or failed, and drops entries from feeds you have disabled.
- **Limited memory.** Building the database spills to disk, so even 48M hashes take about 225 MB of RAM.
- **Empty files.** The empty-file hash appears in some feeds (malware URLs sometimes serve empty responses), so it is always excluded.

Any feed that is a list of hashes (plain text or CSV, optionally zipped) can be added:

```json
{ "name": "internal-ti", "url": "https://ti.example.com/sha256.txt", "format": "text",
  "refresh": "incremental", "header_name": "Authorization", "header_value": "Bearer ${TI_TOKEN}",
  "enabled": true }
```

## Configuration

FileGate looks for its config in this order: `--config`, then `$FILEGATE_CONFIG`, then `/etc/filegate/config.json`. If none exists, it uses a per-user config only when there is no system installation. Run `filegate config show` to print the effective config.

| Key | Default | |
|---|---|---|
| `clamav.enabled` | `required` | `required` / `auto` (use if present) / `off`. Set `clamav.socket` for a non-standard path or `tcp://host:port`. |
| `policy.unscannable` | `error` | What to answer when content can't be inspected: `error`, or `malicious` to fail closed |
| `policy.max_signature_age` | `24h` | Scans answer `retry` and trigger an update when there has been no successful update for this long |
| `policy.require_signatures` | `true` | Answer `retry` when there is no signature database |
| `heuristics.threshold` | `100` | Per-object score that makes a file malicious |
| `limits.max_file_size` | 256 MiB | Largest object analysed in memory. Larger files get hash lookups and ClamAV only. |
| `limits.max_total_extract` / `max_archive_depth` / `max_archive_files` | 1 GiB / 6 / 20000 | Hitting any of these limits gives `error` |
| `update_interval` / `full_refresh_interval` | `1h` / `168h` | |
| `api.listen` | `127.0.0.1:8750` | Use TLS (`tls_cert`/`tls_key`) or a reverse proxy if you expose it |

## Development

```sh
make vet test build
```

The tests build their malicious samples at runtime, and the encrypted-archive fixtures contain only a harmless stand-in file. The fixtures were created with independent tools (pyzipper for AES, Info-ZIP for ZipCrypto) to cross-check FileGate's decryption. A fake clamd tests the ClamAV protocol paths.
