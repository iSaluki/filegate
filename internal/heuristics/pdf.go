package heuristics

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"io"
	"regexp"
)

var (
	pdfHexName   = regexp.MustCompile(`/[A-Za-z0-9]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*`)
	pdfJS        = regexp.MustCompile(`/(javascript|js)[\s/<(\[]`)
	pdfAutoOpen  = regexp.MustCompile(`/(openaction|aa)[\s/<\[]`)
	pdfStreamTag = []byte("stream")
	pdfEndStream = []byte("endstream")
)

// normalizePDFNames decodes #xx escapes in PDF names (e.g. /J#61vaScript),
// a common trick to evade string matching.
func normalizePDFNames(data []byte) ([]byte, bool) {
	changed := false
	out := pdfHexName.ReplaceAllFunc(data, func(m []byte) []byte {
		var b bytes.Buffer
		for i := 0; i < len(m); i++ {
			if m[i] == '#' && i+2 < len(m) {
				if v, err := hex.DecodeString(string(m[i+1 : i+3])); err == nil {
					b.WriteByte(v[0])
					i += 2
					changed = true
					continue
				}
			}
			b.WriteByte(m[i])
		}
		return b.Bytes()
	})
	return out, changed
}

// pdfStreams inflates FlateDecode streams, bounded by total output size.
func pdfStreams(data []byte, budget int) [][]byte {
	var out [][]byte
	for off := 0; off < len(data) && budget > 0 && len(out) < 4096; {
		i := bytes.Index(data[off:], pdfStreamTag)
		if i < 0 {
			break
		}
		start := off + i + len(pdfStreamTag)
		off = start
		// "endstream" also contains "stream"; skip it.
		if i >= 3 && bytes.HasSuffix(data[:start-len(pdfStreamTag)], []byte("end")) {
			continue
		}
		if start < len(data) && data[start] == '\r' {
			start++
		}
		if start < len(data) && data[start] == '\n' {
			start++
		}
		j := bytes.Index(data[start:], pdfEndStream)
		if j < 0 {
			break
		}
		raw := data[start : start+j]
		off = start + j + len(pdfEndStream)
		if len(raw) < 2 {
			continue
		}
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		dec, _ := io.ReadAll(io.LimitReader(zr, int64(min(budget, 32<<20))))
		zr.Close()
		if len(dec) > 0 {
			out = append(out, dec)
			budget -= len(dec)
		}
	}
	return out
}

func analyzePDF(data []byte) ([]Finding, []Child) {
	var out []Finding
	norm, obf := normalizePDFNames(data)
	lower := asciiLower(norm)
	if obf {
		out = append(out, Finding{"Heuristic.PDF.ObfuscatedNames", 25, "uses hex-escaped names to hide keywords"})
	}
	hasJS := pdfJS.Match(lower)
	auto := pdfAutoOpen.Match(lower)
	if hasJS {
		out = append(out, Finding{"Heuristic.PDF.JavaScript", 20, "contains JavaScript"})
		if auto {
			out = append(out, Finding{"Heuristic.PDF.AutoJavaScript", 30, "runs JavaScript automatically on open"})
		}
	}
	if bytes.Contains(lower, []byte("/launch")) {
		out = append(out, Finding{"Heuristic.PDF.Launch", 50, "uses /Launch to run external programs"})
	}
	if bytes.Contains(lower, []byte("/embeddedfile")) {
		out = append(out, Finding{"Heuristic.PDF.EmbeddedFile", 10, "contains embedded files"})
	}
	if bytes.Contains(lower, []byte("/richmedia")) {
		out = append(out, Finding{"Heuristic.PDF.RichMedia", 15, "embeds Flash/RichMedia content"})
	}

	var children []Child
	streams := pdfStreams(data, 64<<20)
	var js bytes.Buffer
	if hasJS {
		js.Write(lower)
	}
	for i, s := range streams {
		ft := Detect(s)
		switch ft {
		case TypePE, TypeELF, TypeOLE, TypeZip, TypeRTF, TypeMachO:
			children = append(children, Child{Name: "stream" + itoa(i), Data: s})
		}
		if hasJS {
			js.WriteByte('\n')
			js.Write(asciiLower(s))
		}
	}
	if hasJS {
		out = append(out, evalIndicators(pdfJSIndicators, js.Bytes())...)
	}
	return out, children
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
