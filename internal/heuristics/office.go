package heuristics

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

var errVBA = errors.New("invalid VBA compressed container")

// DecompressVBA implements the MS-OVBA 2.4.1 decompression algorithm. It
// stops cleanly at the first chunk with an invalid signature, which lets
// callers decompress a module without knowing its exact length.
func DecompressVBA(src []byte, limit int) ([]byte, error) {
	if len(src) < 3 || src[0] != 0x01 {
		return nil, errVBA
	}
	out := make([]byte, 0, 4096)
	pos := 1
	for pos+2 <= len(src) && len(out) < limit {
		header := binary.LittleEndian.Uint16(src[pos:])
		if (header>>12)&0x7 != 0x3 { // chunk signature
			if len(out) == 0 {
				return nil, errVBA
			}
			break
		}
		chunkEnd := min(len(src), pos+int(header&0x0FFF)+3)
		compressed := header&0x8000 != 0
		pos += 2
		if !compressed {
			end := min(len(src), pos+4096)
			out = append(out, src[pos:end]...)
			pos = end
			continue
		}
		chunkStart := len(out)
		for pos < chunkEnd {
			flags := src[pos]
			pos++
			for bit := 0; bit < 8 && pos < chunkEnd; bit++ {
				if flags&(1<<bit) == 0 {
					out = append(out, src[pos])
					pos++
					continue
				}
				if pos+2 > chunkEnd {
					pos = chunkEnd
					break
				}
				token := int(binary.LittleEndian.Uint16(src[pos:]))
				pos += 2
				diff := len(out) - chunkStart
				bitCount := 4
				for (1 << bitCount) < diff {
					bitCount++
				}
				if bitCount > 12 {
					bitCount = 12
				}
				lengthMask := 0xFFFF >> bitCount
				length := (token & lengthMask) + 3
				offset := (token >> (16 - bitCount)) + 1
				from := len(out) - offset
				if from < chunkStart || from < 0 {
					return out, errVBA
				}
				for i := 0; i < length; i++ {
					out = append(out, out[from+i])
				}
			}
		}
		pos = chunkEnd
	}
	return out, nil
}

var attributMarker = []byte("\x00Attribut")

// ExtractVBA finds compressed VBA module source anywhere in data (OLE
// vbaProject.bin, legacy .doc/.xls, MHT/ActiveMime) and returns the
// decompressed source of each module found. Module source always begins with
// "Attribute VB_Name", whose compressed form starts with a literal-only flag
// byte followed by "Attribut", preceded by the container signature and a
// 2-byte chunk header.
func ExtractVBA(data []byte) []string {
	var mods []string
	seen := 0
	for off := 0; off < len(data) && seen < 256; {
		i := bytes.Index(data[off:], attributMarker)
		if i < 0 {
			break
		}
		start := off + i - 3
		off += i + len(attributMarker)
		if start < 0 || data[start] != 0x01 {
			continue
		}
		seen++
		src, err := DecompressVBA(data[start:], 4<<20)
		if err != nil && len(src) == 0 {
			continue
		}
		if bytes.HasPrefix(src, []byte("Attribute VB_")) || bytes.HasPrefix(src, []byte("Attribut")) {
			mods = append(mods, string(src))
		}
	}
	return mods
}

var (
	utf16VBAProject   = []byte("_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00")
	utf16EquationNat  = []byte("E\x00q\x00u\x00a\x00t\x00i\x00o\x00n\x00 \x00N\x00a\x00t\x00i\x00v\x00e\x00")
	utf16EncryptedPkg = []byte("E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e\x00")
	utf16Ole10Native  = []byte("\x01\x00O\x00l\x00e\x001\x000\x00N\x00a\x00t\x00i\x00v\x00e\x00")
)

func analyzeVBA(mods []string) []Finding {
	if len(mods) == 0 {
		return nil
	}
	src := strings.ToLower(strings.Join(mods, "\n"))
	out := []Finding{{"Heuristic.Macro.Present", 10, "document contains VBA macros"}}
	out = append(out, evalIndicators(vbaIndicators, []byte(src))...)
	return out
}

func analyzeOLE(data []byte) []Finding {
	var out []Finding
	mods := ExtractVBA(data)
	if len(mods) == 0 && bytes.Contains(data, utf16VBAProject) {
		out = append(out, Finding{"Heuristic.Macro.Present", 10, "document contains a VBA project"})
	}
	out = append(out, analyzeVBA(mods)...)
	if bytes.Contains(data, utf16EquationNat) || bytes.Contains(data, []byte("Equation.3")) {
		out = append(out, Finding{"Heuristic.Office.EquationEditor", 50, "embeds an Equation Editor object (CVE-2017-11882 / CVE-2018-0802 vector)"})
	}
	if bytes.Contains(data, utf16Ole10Native) {
		out = append(out, Finding{"Heuristic.Office.OLEPackage", 20, "embeds an OLE package (dropped file)"})
	}
	if bytes.Contains(data, utf16EncryptedPkg) {
		out = append(out, Finding{"Heuristic.Office.Encrypted", 10, "password-protected Office document; content cannot be inspected"})
	}
	return out
}

// analyzeOOXMLPart inspects individual XML parts of an OOXML container.
func analyzeOOXMLPart(name string, lower []byte) []Finding {
	var out []Finding
	lname := strings.ToLower(name)
	if strings.HasSuffix(lname, ".rels") {
		if bytes.Contains(lower, []byte("ms-msdt:")) || bytes.Contains(lower, []byte("search-ms:")) {
			out = append(out, Finding{"Heuristic.Office.Follina", 100, "external relationship to ms-msdt/search-ms protocol handler (CVE-2022-30190)"})
		}
		if bytes.Contains(lower, []byte("targetmode=\"external\"")) {
			if bytes.Contains(lower, []byte("attachedtemplate")) {
				out = append(out, Finding{"Heuristic.Office.RemoteTemplate", 60, "loads a remote template (template injection)"})
			}
			if bytes.Contains(lower, []byte("/oleobject")) && bytes.Contains(lower, []byte("mhtml:")) {
				out = append(out, Finding{"Heuristic.Office.RemoteOLE", 70, "remote OLE object via mhtml (CVE-2021-40444 vector)"})
			} else if bytes.Contains(lower, []byte("/oleobject\"")) && bytes.Contains(lower, []byte("target=\"http")) {
				out = append(out, Finding{"Heuristic.Office.RemoteOLE", 40, "loads a remote OLE object"})
			}
			if bytes.Contains(lower, []byte("/frame\"")) && bytes.Contains(lower, []byte("target=\"http")) {
				out = append(out, Finding{"Heuristic.Office.RemoteFrame", 30, "loads a remote frame"})
			}
		}
	}
	if strings.Contains(lname, "macrosheets/") {
		out = append(out, Finding{"Heuristic.Office.XLM.MacroSheet", 30, "contains an Excel 4.0 (XLM) macro sheet"})
		if xlmExec.Match(lower) {
			out = append(out, Finding{"Heuristic.Office.XLM.Exec", 50, "XLM macro executes commands or native code"})
		}
		if bytes.Contains(lower, []byte("urlmon")) || bytes.Contains(lower, []byte("urldownloadtofile")) {
			out = append(out, Finding{"Heuristic.Office.XLM.Download", 30, "XLM macro downloads content"})
		}
	}
	if strings.HasSuffix(lname, "workbook.xml") && bytes.Contains(lower, []byte("_xlnm.auto_open")) {
		out = append(out, Finding{"Heuristic.Office.XLM.AutoOpen", 40, "workbook defines an Auto_Open macro"})
	}
	return out
}

var xlmExec = re(`(exec|call|register|formula\.fill|halt)\s*\(`)

func analyzeRTF(data []byte) []Finding {
	lower := asciiLower(data)
	var out []Finding
	// Attackers split control words with whitespace/garbage; strip it for matching.
	if bytes.Contains(lower, []byte("\\objdata")) {
		out = append(out, Finding{"Heuristic.RTF.EmbeddedObject", 15, "embeds OLE object data"})
	}
	if bytes.Contains(lower, []byte("\\objupdate")) {
		out = append(out, Finding{"Heuristic.RTF.ObjUpdate", 25, "forces embedded objects to load automatically"})
	}
	if bytes.Contains(lower, []byte("equation.3")) || bytes.Contains(lower, []byte("4571756174696f6e2e33")) || bytes.Contains(lower, []byte("4571756174696f6e204e6174697665")) {
		out = append(out, Finding{"Heuristic.RTF.EquationEditor", 60, "embeds an Equation Editor object (CVE-2017-11882 vector)"})
	}
	if bytes.Contains(lower, []byte("\\objclass package")) || bytes.Contains(lower, []byte("5061636b61676500")) {
		out = append(out, Finding{"Heuristic.RTF.Package", 30, "embeds a Packager object (drops files)"})
	}
	if bytes.Contains(lower, []byte("4d5a90000300000004000000ffff")) {
		out = append(out, Finding{"Heuristic.RTF.EmbeddedPE", 50, "hex-encoded Windows executable inside the document"})
	}
	if bytes.Contains(lower, []byte("d0cf11e0a1b11ae1")) && bytes.Contains(lower, []byte("\\objocx")) {
		out = append(out, Finding{"Heuristic.RTF.ActiveX", 25, "embeds ActiveX controls"})
	}
	return out
}

var lnkPadding = re(`\s{80,}`)

var lnkInterpreters = []string{"cmd.exe", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "bitsadmin", "msiexec", "conhost", "forfiles", "curl.exe"}

func analyzeLNK(data []byte) []Finding {
	// Arguments are stored UTF-16LE; dropping NULs yields matchable ASCII.
	txt := asciiLower(bytes.ReplaceAll(data, []byte{0}, nil))
	var out []Finding
	for _, s := range lnkInterpreters {
		if bytes.Contains(txt, []byte(s)) {
			out = append(out, Finding{"Heuristic.LNK.LaunchesInterpreter", 40, "shortcut launches a command interpreter (" + s + ")"})
			break
		}
	}
	if lnkPadding.Match(txt) {
		out = append(out, Finding{"Heuristic.LNK.HiddenArguments", 30, "arguments padded with whitespace to hide them"})
	}
	out = append(out, evalIndicators(scriptIndicators, txt)...)
	return out
}
