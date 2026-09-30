// Package archive unpacks container formats in memory with strict resource
// limits so hostile archives (bombs, quines, deep nesting) cannot exhaust
// the host.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/isaluki/filegate/internal/heuristics"
	"github.com/ulikunitz/xz"
)

// Budget is shared by every archive in a single scan.
type Budget struct {
	Bytes int64 // remaining decompressed bytes
	Files int   // remaining objects
}

// Options configure extraction.
type Options struct {
	MaxEntrySize              int64
	MaxCompressRatio          int
	BlockEncryptedExecutables bool
}

// Result carries findings about the container itself.
type Result struct {
	Findings []heuristics.Finding
	Warnings []string
}

// ErrStop can be returned by the callback to abort extraction.
var ErrStop = errors.New("stop extraction")

// EntryFunc receives each extracted file.
type EntryFunc func(name string, data []byte) error

// Extract unpacks data of type ft and calls fn for each member.
func Extract(ft heuristics.FileType, name string, data []byte, b *Budget, opt Options, fn EntryFunc) Result {
	var r Result
	var err error
	switch ft {
	case heuristics.TypeZip:
		err = extractZip(data, b, opt, fn, &r)
	case heuristics.TypeTar:
		err = extractTar(bytes.NewReader(data), b, opt, fn, &r)
	case heuristics.TypeGzip:
		err = extractStream(name, data, b, opt, fn, &r, func(rd io.Reader) (io.Reader, string, error) {
			zr, err := gzip.NewReader(rd)
			if err != nil {
				return nil, "", err
			}
			return zr, zr.Name, nil
		}, ".gz", ".tgz")
	case heuristics.TypeBzip2:
		err = extractStream(name, data, b, opt, fn, &r, func(rd io.Reader) (io.Reader, string, error) {
			return bzip2.NewReader(rd), "", nil
		}, ".bz2", ".tbz2")
	case heuristics.TypeXZ:
		err = extractStream(name, data, b, opt, fn, &r, func(rd io.Reader) (io.Reader, string, error) {
			zr, err := xz.NewReader(rd)
			return zr, "", err
		}, ".xz", ".txz")
	default:
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %s archives are not unpacked by the built-in engine", name, ft))
		return r
	}
	if err != nil && !errors.Is(err, ErrStop) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", name, err))
	}
	return r
}

func bomb(desc string) heuristics.Finding {
	return heuristics.Finding{Name: "Heuristic.Archive.Bomb", Score: 100, Description: desc}
}

// readBounded reads rd up to the per-entry and budget limits. It reports
// whether the limit was hit.
func readBounded(rd io.Reader, b *Budget, opt Options) ([]byte, bool, error) {
	limit := b.Bytes
	if opt.MaxEntrySize > 0 && opt.MaxEntrySize < limit {
		limit = opt.MaxEntrySize
	}
	if limit < 0 {
		limit = 0
	}
	buf, err := io.ReadAll(io.LimitReader(rd, limit+1))
	over := int64(len(buf)) > limit
	if over {
		buf = buf[:limit]
	}
	b.Bytes -= int64(len(buf))
	return buf, over, err
}

func ratio(out, in int64) int64 {
	if in <= 0 {
		in = 1
	}
	return out / in
}

func unsafePath(name string) bool {
	n := strings.ReplaceAll(name, "\\", "/")
	return strings.HasPrefix(n, "/") || strings.Contains("/"+n+"/", "/../")
}

func extractZip(data []byte, b *Budget, opt Options, fn EntryFunc, r *Result) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("corrupt zip: %w", err)
	}
	encrypted, riskyEncrypted := 0, 0
	var extracted int64
	traversal := false
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if unsafePath(f.Name) {
			traversal = true
		}
		if f.Flags&0x1 != 0 {
			encrypted++
			if heuristics.IsRiskyName(f.Name) {
				riskyEncrypted++
			}
			continue
		}
		if b.Files <= 0 {
			r.Warnings = append(r.Warnings, "object limit reached; remaining archive members not scanned")
			break
		}
		if b.Bytes <= 0 {
			if ratio(extracted, int64(len(data))) >= int64(opt.MaxCompressRatio) {
				r.Findings = append(r.Findings, bomb("archive expands beyond scan limits at an extreme compression ratio (zip bomb)"))
				return ErrStop
			}
			r.Warnings = append(r.Warnings, "decompression budget exhausted; remaining archive members not scanned")
			break
		}
		rc, err := f.Open()
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
			continue
		}
		buf, over, err := readBounded(rc, b, opt)
		rc.Close()
		extracted += int64(len(buf))
		if over {
			// archive/zip refuses to return more than the declared size, so
			// the declared size is a trustworthy measure of expansion.
			if ratio(int64(max(f.UncompressedSize64, uint64(len(buf)))), int64(f.CompressedSize64)) >= int64(opt.MaxCompressRatio) {
				r.Findings = append(r.Findings, bomb(fmt.Sprintf("member %q decompresses beyond limits at >%d:1 (zip bomb)", f.Name, opt.MaxCompressRatio)))
				return ErrStop
			}
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: exceeds size limit; only the first %d bytes were scanned", f.Name, len(buf)))
		}
		if err != nil && !errors.Is(err, zip.ErrChecksum) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", f.Name, err))
		}
		b.Files--
		if err := fn(f.Name, buf); err != nil {
			return err
		}
	}
	if traversal {
		r.Findings = append(r.Findings, heuristics.Finding{Name: "Heuristic.Archive.PathTraversal", Score: 40, Description: "archive members escape the extraction directory (zip slip)"})
	}
	if encrypted > 0 {
		r.Findings = append(r.Findings, heuristics.Finding{Name: "Heuristic.Archive.Encrypted", Score: 10,
			Description: fmt.Sprintf("%d password-protected member(s) could not be inspected", encrypted)})
		if riskyEncrypted > 0 && opt.BlockEncryptedExecutables {
			r.Findings = append(r.Findings, heuristics.Finding{Name: "Heuristic.Archive.EncryptedExecutable", Score: 90,
				Description: "password-protected archive hides executables/scripts (common malware delivery technique)"})
		}
	}
	return nil
}

func extractTar(rd io.Reader, b *Budget, opt Options, fn EntryFunc, r *Result) error {
	tr := tar.NewReader(rd)
	traversal := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("corrupt tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		if unsafePath(h.Name) {
			traversal = true
		}
		if b.Files <= 0 || b.Bytes <= 0 {
			r.Warnings = append(r.Warnings, "scan limits reached; remaining tar members not scanned")
			break
		}
		buf, over, err := readBounded(tr, b, opt)
		if err != nil {
			return err
		}
		if over {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: exceeds size limit; only the first %d bytes were scanned", h.Name, len(buf)))
		}
		b.Files--
		if err := fn(h.Name, buf); err != nil {
			return err
		}
	}
	if traversal {
		r.Findings = append(r.Findings, heuristics.Finding{Name: "Heuristic.Archive.PathTraversal", Score: 40, Description: "archive members escape the extraction directory"})
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type opener func(io.Reader) (io.Reader, string, error)

func extractStream(name string, data []byte, b *Budget, opt Options, fn EntryFunc, r *Result, open opener, exts ...string) error {
	src := &countingReader{r: bytes.NewReader(data)}
	rd, inner, err := open(src)
	if err != nil {
		return err
	}
	if b.Files <= 0 || b.Bytes <= 0 {
		r.Warnings = append(r.Warnings, "scan limits reached; compressed stream not scanned")
		return nil
	}
	buf, over, err := readBounded(rd, b, opt)
	if over {
		// Compare output against the compressed input consumed so far.
		if ratio(int64(len(buf)), src.n) >= int64(opt.MaxCompressRatio) {
			r.Findings = append(r.Findings, bomb(fmt.Sprintf("stream decompresses beyond limits at >%d:1 (compression bomb)", opt.MaxCompressRatio)))
			return ErrStop
		}
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: decompressed data exceeds size limit; only the first %d bytes were scanned", name, len(buf)))
	}
	if err != nil && len(buf) == 0 {
		return err
	}
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v (partial data scanned)", name, err))
	}
	if inner == "" {
		inner = innerName(path.Base(name), exts)
	}
	b.Files--
	return fn(inner, buf)
}

func innerName(base string, exts []string) string {
	lb := strings.ToLower(base)
	for _, e := range exts {
		if strings.HasSuffix(lb, e) {
			stem := base[:len(base)-len(e)]
			if strings.HasPrefix(e, ".t") && len(e) > 3 { // .tgz/.tbz2/.txz
				return stem + ".tar"
			}
			return stem
		}
	}
	if base == "" || base == "." || base == "/" {
		return "data"
	}
	return base + ".decompressed"
}
