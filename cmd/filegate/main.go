// Command filegate is a malware scanner for files and archives with an
// optional authenticated REST API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/isaluki/filegate/internal/api"
	"github.com/isaluki/filegate/internal/apikey"
	"github.com/isaluki/filegate/internal/config"
	"github.com/isaluki/filegate/internal/scanner"
	"github.com/isaluki/filegate/internal/service"
	"github.com/isaluki/filegate/internal/updater"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	exitSafe      = 0
	exitMalicious = 1
	exitError     = 2
	exitRetry     = 3
)

const usage = `FileGate - fast malware verdicts for files and archives

Usage:
  filegate [--config PATH] <command> [options]

Commands:
  scan <path|->...        Scan files, directories or stdin ("-"); prints safe/malicious
  update                  Download the latest signature databases
  status                  Show engine and signature database status
  serve                   Run the REST API in the foreground
  apikey create|list|revoke
                          Manage API keys for the REST API
  service install|uninstall|status
                          Manage the systemd units (API service + update timer)
  config show|init        Print the effective config / write a default config file
  version                 Print the version

Exit codes for scan:
  0 = all files safe
  1 = malicious content found
  2 = error: a file could not be fully inspected (e.g. password-protected
      archive without --password) or an engine is unavailable; never treat as safe
  3 = retry: the signature database is being downloaded; run the scan again
      shortly
Run 'filegate <command> -h' for command options.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("filegate", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.Usage = func() { fmt.Fprint(stderr, usage) }
	cfgPath := global.String("config", "", "config file (default: /etc/filegate/config.json or ~/.config/filegate/config.json)")
	showVersion := global.Bool("version", false, "print version")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSafe
		}
		return exitError
	}
	if *showVersion {
		fmt.Fprintln(stdout, "filegate", version)
		return exitSafe
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	cmd, cargs := rest[0], rest[1:]
	if cmd == "version" {
		fmt.Fprintf(stdout, "filegate %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return exitSafe
	}
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		fmt.Fprint(stdout, usage)
		return exitSafe
	}
	updater.UserAgent = fmt.Sprintf("FileGate/%s (+https://github.com/isaluki/filegate)", version)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var code int
	switch cmd {
	case "scan":
		code, err = cmdScan(ctx, cfg, cargs, stdout, stderr)
	case "update":
		code, err = cmdUpdate(ctx, cfg, cargs, stdout, stderr)
	case "status":
		code, err = cmdStatus(ctx, cfg, cargs, stdout, stderr)
	case "serve":
		code, err = cmdServe(ctx, cfg, cargs, stdout, stderr)
	case "apikey", "apikeys", "key", "keys":
		code, err = cmdAPIKey(cfg, cargs, stdout, stderr)
	case "service":
		code, err = cmdService(cfg, cargs, stdout, stderr)
	case "config":
		code, err = cmdConfig(cfg, cargs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "error:", err)
		}
		if code == exitSafe {
			code = exitError
		}
	}
	return code
}

func newFlags(name string, stderr io.Writer, help string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: filegate %s\n\nOptions:\n", help)
		fs.PrintDefaults()
	}
	return fs
}

// ---------------------------------------------------------------- scan

func cmdScan(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("scan", stderr, "scan [options] <file|dir|->...")
	jsonOut := fs.Bool("json", false, "output results as JSON (one object per line)")
	quiet := fs.Bool("quiet", false, "only print malicious files")
	verbose := fs.Bool("v", false, "show all detections, including low-score heuristics, and warnings")
	jobs := fs.Int("jobs", runtime.NumCPU(), "parallel scans when scanning directories")
	noHeur := fs.Bool("no-heuristics", false, "disable the heuristic engine (signatures only)")
	noClam := fs.Bool("no-clamav", false, "do not use ClamAV even if available")
	name := fs.String("name", "", "file name to assume when scanning stdin")
	noSigs := fs.Bool("allow-no-signatures", false, "scan even if the signature database is missing or stale (NOT recommended)")
	password := fs.String("password", "", "password for password-protected archives (FileGate never guesses passwords)")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitError, errors.New("no files given")
	}
	if *noHeur {
		cfg.Heuristics.Enabled = false
	}
	if *noClam {
		cfg.ClamAV.Enabled = "off"
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		return exitError, err
	}
	if *noSigs {
		cfg.Policy.RequireSignatures = false
	}
	if code, err := scanGate(ctx, cfg, sc, fs.Args(), *jsonOut, stdout, stderr); code != exitSafe || err != nil {
		return code, err
	}
	opts := scanner.Options{Password: *password}

	var mu sync.Mutex
	malicious, failed := 0, 0
	enc := json.NewEncoder(stdout)
	report := func(r *scanner.Result, err error, path string) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed++
			if *jsonOut {
				_ = enc.Encode(map[string]string{"file": path, "error": err.Error()})
			} else {
				fmt.Fprintf(stderr, "%s: ERROR %v\n", path, err)
			}
			return
		}
		if r.Malicious() {
			malicious++
		} else if r.Failed() {
			failed++
		}
		if *jsonOut {
			_ = enc.Encode(r)
			return
		}
		printResult(stdout, r, *quiet, *verbose)
	}

	paths := make(chan string, 64)
	var wg sync.WaitGroup
	for i := 0; i < max(1, *jobs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range paths {
				r, err := sc.ScanFileWith(ctx, p, opts)
				report(r, err, p)
			}
		}()
	}

	for _, arg := range fs.Args() {
		if ctx.Err() != nil {
			break
		}
		if arg == "-" {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, cfg.Limits.MaxFileSize+1))
			if err == nil && int64(len(data)) > cfg.Limits.MaxFileSize {
				err = fmt.Errorf("stdin exceeds max_file_size (%d bytes)", cfg.Limits.MaxFileSize)
			}
			if err != nil {
				report(nil, err, "-")
				continue
			}
			n := *name
			if n == "" {
				n = "stdin"
			}
			report(sc.ScanBytesWith(ctx, n, data, opts), nil, "-")
			continue
		}
		fi, err := os.Stat(arg)
		if err != nil {
			report(nil, err, arg)
			continue
		}
		if !fi.IsDir() {
			paths <- arg
			continue
		}
		_ = filepath.WalkDir(arg, func(p string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				report(nil, err, p)
				return nil
			}
			if d.Type().IsRegular() {
				paths <- p
			}
			return nil
		})
	}
	close(paths)
	wg.Wait()

	if ctx.Err() != nil {
		return exitError, errors.New("interrupted")
	}
	switch {
	case malicious > 0:
		return exitMalicious, nil
	case failed > 0:
		return exitError, nil
	}
	return exitSafe, nil
}

// scanGate checks that verdicts will be trustworthy before scanning. When
// the signature database is missing or stale it starts an update in the
// background and answers "retry" (exit 3) for every file.
func scanGate(ctx context.Context, cfg *config.Config, sc *scanner.Scanner, files []string, jsonOut bool, stdout, stderr io.Writer) (int, error) {
	rd := updater.Check(cfg, sc.SignatureCount())
	switch {
	case rd.Err != nil:
		return exitError, fmt.Errorf("%w [data dir: %s]", rd.Err, cfg.DataDir)
	case rd.NeedUpdate:
		if !updater.CanWrite(cfg) {
			return exitError, fmt.Errorf("%s, and this user cannot update it in %s; run 'sudo filegate update'",
				strings.TrimSuffix(rd.Reason, "; an update has been started"), cfg.DataDir)
		}
		if err := updater.StartDetached(cfg); err != nil {
			return exitError, fmt.Errorf("starting signature update: %w", err)
		}
		fallthrough
	case rd.Updating:
		secs := int(updater.RetryAfter.Seconds())
		for _, f := range files {
			if jsonOut {
				_ = json.NewEncoder(stdout).Encode(map[string]any{"file": f, "verdict": scanner.VerdictRetry,
					"reason": rd.Reason, "retry_after_seconds": secs})
			} else {
				fmt.Fprintf(stdout, "%s: RETRY (%s)\n", f, rd.Reason)
			}
		}
		if !jsonOut {
			fmt.Fprintf(stderr, "Run the scan again in about %ds (progress: %s).\n", secs, filepath.Join(cfg.DataDir, "update.log"))
		}
		return exitRetry, nil
	}
	if err := sc.ClamAVReady(ctx); err != nil {
		return exitError, err
	}
	return exitSafe, nil
}

func printResult(w io.Writer, r *scanner.Result, quiet, verbose bool) {
	if r.Failed() {
		fmt.Fprintf(w, "%s: ERROR %s\n", r.File, r.Error)
		if verbose || len(r.Unscannable) > 1 {
			for _, u := range r.Unscannable {
				if u.Object != "" {
					fmt.Fprintf(w, "    cannot inspect %s: %s\n", u.Object, u.Reason)
				} else {
					fmt.Fprintf(w, "    cannot inspect: %s\n", u.Reason)
				}
			}
		}
		printDetails(w, r, verbose)
		return
	}
	if !r.Malicious() {
		if quiet {
			return
		}
		note := ""
		if r.Allowlisted {
			note = " (allowlisted)"
		}
		fmt.Fprintf(w, "%s: safe%s\n", r.File, note)
		if verbose {
			printDetails(w, r, true)
		}
		return
	}
	var names []string
	for _, d := range r.Detections { // sorted by score, highest first
		if len(names) == 3 || (len(names) > 0 && d.Score < 20) {
			break
		}
		names = append(names, d.Name)
	}
	fmt.Fprintf(w, "%s: MALICIOUS (%s)\n", r.File, strings.Join(names, ", "))
	printDetails(w, r, verbose)
}

func printDetails(w io.Writer, r *scanner.Result, verbose bool) {
	for _, d := range r.Detections {
		if !verbose && d.Score < 20 {
			continue
		}
		fmt.Fprintf(w, "    [%3d] %-9s %s  in %s", d.Score, d.Engine, d.Name, d.Object)
		if d.Description != "" && verbose {
			fmt.Fprintf(w, " - %s", d.Description)
		}
		fmt.Fprintln(w)
	}
	if verbose {
		for _, warn := range r.Warnings {
			fmt.Fprintf(w, "    warning: %s\n", warn)
		}
		fmt.Fprintf(w, "    sha256=%s type=%s objects=%d score=%d time=%.1fms\n", r.SHA256, r.Type, r.ObjectsScanned, r.Score, r.DurationMS)
	}
}

// ---------------------------------------------------------------- update

func cmdUpdate(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("update", stderr, "update [options]")
	full := fs.Bool("full", false, "force a full rebuild from all feeds")
	quiet := fs.Bool("quiet", false, "only print errors")
	jsonOut := fs.Bool("json", false, "print the update report as JSON")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	var logw io.Writer = stdout
	if *quiet || *jsonOut {
		logw = nil
	}
	rep, err := updater.Run(ctx, cfg, updater.Options{Force: *full, Log: logw})
	if errors.Is(err, updater.ErrLocked) {
		if !*quiet {
			fmt.Fprintln(stderr, "another update is already running; skipping")
		}
		return exitSafe, nil
	}
	if os.IsPermission(errors.Unwrap(err)) || os.IsPermission(err) {
		return exitError, fmt.Errorf("%w (data dir %s; try sudo)", err, cfg.DataDir)
	}
	if rep != nil {
		if *jsonOut {
			e := json.NewEncoder(stdout)
			e.SetIndent("", "  ")
			_ = e.Encode(rep)
		} else if !*quiet {
			kind := "incremental"
			if rep.Full {
				kind = "full"
			}
			fmt.Fprintf(stdout, "%s update finished in %s: %d signatures (was %d)\n", kind,
				time.Duration(rep.DurationMS)*time.Millisecond, rep.After, rep.Before)
		}
	}
	if err != nil {
		return exitError, err
	}
	return exitSafe, nil
}

// ---------------------------------------------------------------- status

func cmdStatus(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("status", stderr, "status [--json]")
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		return exitError, err
	}
	info := sc.Info(ctx)
	st := updater.LoadState(cfg)
	keys, _ := apikey.NewStore(cfg.KeysPath()).List()
	if *jsonOut {
		e := json.NewEncoder(stdout)
		e.SetIndent("", "  ")
		_ = e.Encode(map[string]any{"version": version, "config": cfg.Path(), "data_dir": cfg.DataDir,
			"engines": info, "updates": st, "api_keys": len(keys)})
		return exitSafe, nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Version:\t%s\n", version)
	fmt.Fprintf(tw, "Config:\t%s\n", cfg.Path())
	fmt.Fprintf(tw, "Data dir:\t%s\n", cfg.DataDir)
	fmt.Fprintf(tw, "Signatures:\t%d (%s)\n", info.SignatureCount, strings.Join(info.SignatureSources, ", "))
	if !info.SignatureDBDate.IsZero() {
		fmt.Fprintf(tw, "Database built:\t%s (%s ago)\n", info.SignatureDBDate.Format(time.RFC3339), time.Since(info.SignatureDBDate).Round(time.Minute))
	}
	fmt.Fprintf(tw, "Custom signatures:\t%d\n", info.CustomSignatures)
	fmt.Fprintf(tw, "Allowlisted hashes:\t%d\n", info.Allowlisted)
	fmt.Fprintf(tw, "Heuristics:\t%v (threshold %d)\n", info.Heuristics, cfg.Heuristics.Threshold)
	clam := info.ClamAV
	if info.ClamAVVersion != "" {
		clam += " - " + info.ClamAVVersion
	}
	fmt.Fprintf(tw, "ClamAV:\t%s\n", clam)
	if err := sc.ClamAVReady(ctx); err != nil {
		defer fmt.Fprintf(stdout, "\n%v\n", err)
	}
	fmt.Fprintf(tw, "Last update:\t%s\n", fmtTime(st.LastUpdate))
	fmt.Fprintf(tw, "Last full refresh:\t%s\n", fmtTime(st.LastFull))
	if st.LastError != "" {
		fmt.Fprintf(tw, "Last update error:\t%s\n", st.LastError)
	}
	names := make([]string, 0, len(st.Feeds))
	for n := range st.Feeds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := st.Feeds[n]
		line := fmt.Sprintf("%d hashes, last success %s", f.Hashes, fmtTime(f.LastSuccess))
		if f.LastError != "" {
			line += ", last error: " + f.LastError
		}
		fmt.Fprintf(tw, "  feed %s:\t%s\n", n, line)
	}
	fmt.Fprintf(tw, "API keys:\t%d\n", len(keys))
	fmt.Fprintf(tw, "API listen:\t%s\n", cfg.API.Listen)
	tw.Flush()
	return exitSafe, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmt.Sprintf("%s (%s ago)", t.Format(time.RFC3339), time.Since(t).Round(time.Second))
}

// ---------------------------------------------------------------- serve

func cmdServe(ctx context.Context, cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlags("serve", stderr, "serve [options]")
	listen := fs.String("listen", cfg.API.Listen, "address to listen on")
	autoUpdate := fs.Bool("auto-update", cfg.API.AutoUpdate, "run signature updates from within the server (not needed when the systemd timer is installed)")
	if err := fs.Parse(args); err != nil {
		return exitError, err
	}
	cfg.API.Listen = *listen
	cfg.API.AutoUpdate = *autoUpdate
	log := slog.New(slog.NewJSONHandler(stderr, nil))

	sc, err := scanner.New(cfg)
	if err != nil {
		return exitError, err
	}
	keys, err := apikey.NewVerifier(apikey.NewStore(cfg.KeysPath()))
	if err != nil {
		return exitError, fmt.Errorf("loading API keys: %w", err)
	}
	if keys.Count() == 0 {
		log.Warn("no API keys configured; all authenticated requests will be rejected. Create one with 'filegate apikey create --name NAME'", "keys_file", cfg.KeysPath())
	}
	info := sc.Info(ctx)
	log.Info("engines loaded", "signatures", info.SignatureCount, "custom", info.CustomSignatures, "heuristics", info.Heuristics, "clamav", info.ClamAV)
	if err := api.New(cfg, sc, keys, log, version).Run(ctx); err != nil {
		return exitError, err
	}
	return exitSafe, nil
}

// ---------------------------------------------------------------- apikey

func cmdAPIKey(cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	const help = "apikey create --name NAME [--ttl DURATION] | list | revoke <id|name>"
	if len(args) == 0 {
		fmt.Fprintf(stderr, "Usage: filegate %s\n", help)
		return exitError, errors.New("missing subcommand")
	}
	store := apikey.NewStore(cfg.KeysPath())
	switch args[0] {
	case "create", "new", "add":
		fs := newFlags("apikey create", stderr, "apikey create --name NAME [--ttl DURATION]")
		name := fs.String("name", "", "a label for the key (e.g. the client using it)")
		ttl := fs.Duration("ttl", 0, "optional lifetime, e.g. 720h (default: never expires)")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError, err
		}
		if *name == "" && fs.NArg() > 0 {
			*name = fs.Arg(0)
		}
		plain, k, err := store.Create(*name, *ttl)
		if err != nil {
			if os.IsPermission(errors.Unwrap(err)) || os.IsPermission(err) {
				return exitError, fmt.Errorf("%w (keys file %s; try sudo)", err, store.Path())
			}
			return exitError, err
		}
		fmt.Fprintf(stderr, "Created API key %q (id %s). Store it now - it cannot be shown again.\n", k.Name, k.ID)
		fmt.Fprintln(stdout, plain)
		return exitSafe, nil
	case "list", "ls":
		keys, err := store.List()
		if err != nil {
			return exitError, err
		}
		if len(keys) == 0 {
			fmt.Fprintln(stdout, "no API keys (create one with 'filegate apikey create --name NAME')")
			return exitSafe, nil
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCREATED\tEXPIRES")
		for _, k := range keys {
			exp := "never"
			if !k.Expires.IsZero() {
				exp = k.Expires.Format(time.RFC3339)
				if k.Expired(time.Now()) {
					exp += " (expired)"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.ID, k.Name, k.Created.Format(time.RFC3339), exp)
		}
		tw.Flush()
		return exitSafe, nil
	case "revoke", "delete", "rm":
		if len(args) < 2 {
			return exitError, errors.New("usage: filegate apikey revoke <id|name>")
		}
		k, err := store.Revoke(args[1])
		if err != nil {
			return exitError, err
		}
		fmt.Fprintf(stdout, "revoked key %q (%s)\n", k.Name, k.ID)
		return exitSafe, nil
	}
	return exitError, fmt.Errorf("unknown apikey subcommand %q (usage: filegate %s)", args[0], help)
}

// ---------------------------------------------------------------- service

func cmdService(cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	const help = "service install [--api] [--listen ADDR] | uninstall | status"
	if len(args) == 0 {
		fmt.Fprintf(stderr, "Usage: filegate %s\n", help)
		return exitError, errors.New("missing subcommand")
	}
	switch args[0] {
	case "install":
		fs := newFlags("service install", stderr, "service install [--api] [--listen ADDR]")
		withAPI := fs.Bool("api", false, "also install and start the REST API service")
		listen := fs.String("listen", "", "API listen address to write to the system config (e.g. 0.0.0.0:8750)")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError, err
		}
		if err := service.Install(cfg, service.Options{EnableAPI: *withAPI, Listen: *listen, Out: stdout}); err != nil {
			return exitError, err
		}
		fmt.Fprintln(stdout, "\nFileGate installed: signature updates run via filegate-update.timer.")
		if *withAPI {
			fmt.Fprintln(stdout, "REST API enabled (filegate.service). Create a key with: sudo filegate apikey create --name <client>")
		}
		return exitSafe, nil
	case "uninstall", "remove":
		return exitSafe, service.Uninstall(stdout)
	case "status":
		return exitSafe, service.Status(stdout)
	}
	return exitError, fmt.Errorf("unknown service subcommand %q (usage: filegate %s)", args[0], help)
}

// ---------------------------------------------------------------- config

func cmdConfig(cfg *config.Config, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 || args[0] == "show" {
		e := json.NewEncoder(stdout)
		e.SetIndent("", "  ")
		fmt.Fprintf(stderr, "# effective config (%s)\n", cfg.Path())
		return exitSafe, e.Encode(cfg)
	}
	if args[0] == "init" {
		fs := newFlags("config init", stderr, "config init [--force]")
		force := fs.Bool("force", false, "overwrite an existing config file")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError, err
		}
		if _, err := os.Stat(cfg.Path()); err == nil && !*force {
			return exitError, fmt.Errorf("%s already exists (use --force to overwrite)", cfg.Path())
		}
		if err := cfg.Save(); err != nil {
			return exitError, err
		}
		fmt.Fprintln(stdout, "wrote", cfg.Path())
		return exitSafe, nil
	}
	return exitError, fmt.Errorf("unknown config subcommand %q (usage: filegate config show|init)", args[0])
}
