# FileGate

FileGate is a malware scanner for Linux. You give it a file or an archive and it returns a `safe` or `malicious` verdict, usually within milliseconds. It works as a CLI, and it can also run an optional REST API as a hardened systemd service. The API uses API keys that you create with the CLI.

It ships as a single static Go binary with no runtime dependencies.

```
$ filegate scan invoice.zip
invoice.zip: MALICIOUS (Heuristic.Macro.PowerShell, Heuristic.Macro.Shell, Heuristic.Macro.Download)
    [ 40] heuristic Heuristic.Macro.PowerShell  in invoice.zip!invoice.docm!word/vbaProject.bin
    [ 35] heuristic Heuristic.Macro.Shell  in invoice.zip!invoice.docm!word/vbaProject.bin
    [ 35] heuristic Heuristic.Macro.Download  in invoice.zip!invoice.docm!word/vbaProject.bin
    [ 30] heuristic Heuristic.Macro.AutoExec  in invoice.zip!invoice.docm!word/vbaProject.bin
```

## Detection engines

| Engine | What it does |
|---|---|
| **Signature DB** | Checks SHA-256 hashes against about 1.1M known-malware hashes from [MalwareBazaar](https://bazaar.abuse.ch). The database is memory-mapped and binary-searched, so it loads instantly and each lookup is O(log n). Every object inside an archive is hash-checked too. |
| **Heuristics** | Static analysis covering: <br>• **PE**: packers, W+X sections, encrypted code, entry-point anomalies, and injection/hollowing/keylogger import sets <br>• **ELF**: UPX packing, W+X segments, IoT-botnet and cryptominer strings <br>• **Office VBA**: a full MS-OVBA decompressor recovers macro source, which is checked for auto-exec plus shell/download/Win32-API/shellcode behaviour <br>• **Other Office**: XLM macros, Follina (`ms-msdt:`), remote template/OLE injection <br>• **RTF**: Equation Editor exploits and embedded PEs <br>• **PDF**: `#xx`-obfuscated names, auto-run JavaScript, `/Launch`; Flate streams are inflated so JS heap sprays and exploit APIs are visible <br>• **LNK**: shortcuts that launch interpreters <br>• **Scripts** (PowerShell, JS/VBS/HTA, batch, shell, Python, PHP): download cradles, encoded commands, AMSI bypass, reverse shells, web shells, ransomware shadow-copy deletion, miners <br>• **File names**: double extensions, RTL-override tricks, and executables disguised as documents |
| **Archives** | Unpacks zip (including OOXML/JAR/APK), tar, gzip, bzip2 and xz recursively in memory. Archives nested inside other formats are handled too, and executables embedded in PDFs are extracted and scanned. Hard limits on size, file count, depth and compression ratio catch zip/gzip bombs and recursive "quine" archives. Password-protected archives that hide executables are flagged, and so are zip-slip paths. |
| **ClamAV** (optional) | If `clamd` is running, FileGate finds its socket automatically and streams every top-level file to it in parallel. This adds ClamAV's signatures and its 7z/RAR/CAB/ISO unpackers. |
| **Custom / allowlist** | Add your own hash signatures in `<data_dir>/signatures/*.txt`, and hashes you know are safe in `<data_dir>/allowlist/*.txt`. Use the allowlist to override false positives. |

### How the verdict works

Each finding has a score. For each object (a file, or a member of an archive), FileGate adds up the scores of its findings. If any object reaches the **threshold** (default `100`), the verdict is `malicious`.

Some findings reach the threshold on their own: a signature match, EICAR, a zip bomb, an AMSI bypass or a Follina payload. Weaker signals only reach it in combination. For example, a macro that runs on open (30), starts a shell (35) and launches PowerShell (40) scores 105.

The heuristics are tuned for a low false-positive rate. In a test scan of 22,282 benign files (1.46 GB of `/usr/bin`, `/usr/lib`, `/usr/share`, `/etc` and the Go source tree), none were flagged, and the highest benign score was 35.

### Speed

On the same corpus, the median scan took 0.075 ms per file and the 99th percentile took 16 ms. The whole corpus finished in about 13 s on 4 cores. A 2 MB Windows PE takes about 35 ms and a 100 MB ELF about 0.7 s. The hash database holds over 1.1M entries and loads instantly because it is memory-mapped.

## Install

Requires Linux with systemd. Building from source needs Go 1.24+.

```sh
make build                          # -> bin/filegate (static binary)
sudo ./scripts/install.sh           # CLI + hourly signature updates (systemd timer)
sudo ./scripts/install.sh --api     # ...and the REST API service
sudo ./scripts/install.sh --api --listen 0.0.0.0:8750
```

`filegate service install` does the following:

1. Copies the binary to `/usr/local/bin/filegate`.
2. Creates an unprivileged `filegate` system user.
3. Writes `/etc/filegate/config.json` and creates `/var/lib/filegate`.
4. Installs and starts these units:
   - `filegate-update.timer`: hourly incremental signature updates, plus a full refresh every 7 days.
   - `filegate.service`: the API. Installed only with `--api`, and sandboxed with `ProtectSystem=strict`, `NoNewPrivileges`, a syscall filter and similar hardening.

The first signature download starts right away.

For extra coverage, install ClamAV (`apt install clamav-daemon`). FileGate adds itself to the `clamav` group so it can reach the socket.

## CLI

```
filegate scan <file|dir|->...   Scan files, directories (recursive) or stdin
    --json          one JSON result per line
    --quiet         only print malicious files
    -v              show every finding, warnings, hash, timing
    --jobs N        parallel scans (default: #CPUs)
    --no-heuristics / --no-clamav
filegate update [--full] [--quiet] [--json]
filegate status [--json]
filegate serve [--listen ADDR] [--auto-update]
filegate apikey create --name NAME [--ttl 720h] | list | revoke <id|name>
filegate service install [--api] [--listen ADDR] | uninstall | status
filegate config show | init
```

`scan` exit codes: `0` means all files are safe, `1` means at least one is malicious, and `2` means an error occurred. This makes it easy to use in scripts:

```sh
filegate scan --quiet "$UPLOAD" || quarantine "$UPLOAD"
```

## REST API

Create a key. The key is printed once; only its SHA-256 hash is stored, in `/etc/filegate/keys.json` (mode 0640).

```sh
sudo filegate apikey create --name webapp
fg_mfzw4y3...
```

Send the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. When you create or revoke a key, the running server picks up the change within seconds, with no restart.

| Method & path | Auth | Description |
|---|---|---|
| `POST /v1/scan` | ✔ | Scan an upload. Send it as a raw request body (optional `?filename=`) or as a multipart form field named `file`. |
| `GET /v1/hash/{sha256}` | ✔ | Look up a hash without uploading the file. |
| `GET /v1/status` | ✔ | Engine and database status, and last update. |
| `GET /v1/health` | – | Liveness probe. |

```sh
curl -H "Authorization: Bearer $KEY" -F file=@suspicious.zip http://127.0.0.1:8750/v1/scan
curl -H "Authorization: Bearer $KEY" --data-binary @a.exe "http://127.0.0.1:8750/v1/scan?filename=a.exe"
```

```json
{
  "file": "eicar.txt",
  "size": 68,
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "type": "text",
  "verdict": "malicious",
  "score": 100,
  "detections": [
    { "engine": "heuristic", "name": "EICAR-Test-File", "object": "eicar.txt",
      "score": 100, "description": "EICAR anti-malware test file" }
  ],
  "objects_scanned": 1,
  "duration_ms": 0.477
}
```

The server caps concurrent scans (`max_concurrent_scans`) and upload size (`max_upload_size`, 256 MiB by default). It logs one JSON line per request and reloads the signature database when the database changes. The API listens on `127.0.0.1:8750` by default. If you expose it beyond localhost, set `tls_cert` and `tls_key`, or put it behind a TLS reverse proxy (and set `trust_proxy_headers`).

## Signature updates

`filegate update` pulls the feeds listed in the config. The defaults are:

- `malwarebazaar-full`: the full SHA-256 export, fetched on the first run and every `full_refresh_interval` (7 days).
- `malwarebazaar-recent`: hashes from the last 48 hours, fetched on every update using ETag caching.

If a full refresh fails, FileGate keeps the existing hashes rather than dropping them. Concurrent updates are serialised with a file lock, and each database is written to a temporary file and atomically renamed, so scanners never see a partial database.

Feeds are plain lists of hashes (`text`) or a zip of such lists (`zip`). You can add your own:

```json
{ "name": "internal-ti", "url": "https://ti.example.com/sha256.txt", "format": "text",
  "refresh": "incremental", "header_name": "Authorization", "header_value": "Bearer ${TI_TOKEN}",
  "enabled": true }
```

`header_value` expands environment variables. For abuse.ch feeds that need an Auth-Key, set `header_name` to `Auth-Key`.

## Configuration

FileGate looks for its config in this order: `--config`, then `$FILEGATE_CONFIG`, then `/etc/filegate/config.json`. If none of those exists and you are not root, it uses `~/.config/filegate/config.json` with data in `~/.local/share/filegate`. Run `filegate config show` to print the effective config.

| Key | Default | |
|---|---|---|
| `data_dir` | `/var/lib/filegate` | Signature DB, update state, custom signatures and allowlist |
| `update_interval` / `full_refresh_interval` | `1h` / `168h` | |
| `heuristics.threshold` | `100` | Per-object score that makes a file malicious |
| `heuristics.block_encrypted_executables` | `true` | Flag password-protected archives that contain executables or scripts |
| `limits.max_file_size` | 256 MiB | Largest object analysed in memory. Larger files still get a hash lookup and ClamAV. |
| `limits.max_total_extract` | 1 GiB | Decompression budget per scan |
| `limits.max_archive_depth` / `max_archive_files` | `6` / `20000` | |
| `limits.max_compress_ratio` | `100` | Expansion ratio above which an oversized member counts as a bomb |
| `clamav.enabled` | `auto` | `auto` / `on` / `off`. `clamav.socket` accepts a unix path or `tcp://host:port`. |
| `clamav.run_freshclam` | `false` | Run `freshclam` during updates (most distros already run the freshclam service) |
| `api.listen` | `127.0.0.1:8750` | |
| `api.auto_update` | `false` | Run updates inside the server. Not needed when the systemd timer is installed. |

## Development

```sh
make vet test build
```

The tests generate their malicious samples at runtime (EICAR, VBA macro droppers, Follina, weaponised PDFs, LNK and RTF files, zip and gzip bombs, and more), so the repository contains no live malware.
