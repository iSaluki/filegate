package heuristics

import (
	"bytes"
	"path"
	"regexp"
	"strings"
)

// Child is an embedded object extracted during analysis (e.g. a file
// dropped from a PDF stream) that should itself be scanned.
type Child struct {
	Name string
	Data []byte
}

const maxTextAnalysis = 16 << 20

// eicar is assembled at runtime so this source file is not itself flagged by
// antivirus products.
var eicar = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` + `!$H+H*`)

var (
	rloChar   = "‮"
	doubleExt = regexp.MustCompile(`\.(pdf|docx?|xlsx?|pptx?|rtf|txt|jpe?g|png|gif|bmp|mp3|mp4|avi|mov|zip|rar|csv|html?)[\s_.]*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|lnk|ps1|msi|cpl|jar|iso|img|vhdx?)$`)
	docExts   = map[string]bool{".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".txt": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".mp3": true, ".mp4": true, ".rtf": true, ".csv": true}
	riskyExts = map[string]bool{".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true, ".cmd": true, ".js": true, ".jse": true, ".vbs": true, ".vbe": true, ".wsf": true, ".wsh": true, ".hta": true, ".lnk": true, ".ps1": true, ".msi": true, ".cpl": true, ".jar": true, ".dll": true, ".iso": true, ".img": true, ".vhd": true, ".vhdx": true, ".docm": true, ".xlsm": true, ".pptm": true, ".one": true}
)

// IsEICAR reports whether data is the EICAR anti-malware test file.
func IsEICAR(data []byte) bool {
	if len(data) > 4096 {
		return false
	}
	return bytes.Contains(data, eicar)
}

// IsRiskyName reports whether a file name has an executable/script extension.
func IsRiskyName(name string) bool {
	return riskyExts[strings.ToLower(path.Ext(name))]
}

// NameFindings flags deceptive file names.
func NameFindings(name string, ft FileType) []Finding {
	var out []Finding
	base := strings.ToLower(path.Base(name))
	if strings.Contains(base, rloChar) {
		out = append(out, Finding{"Heuristic.Name.RightToLeftOverride", 80, "file name uses a right-to-left override to disguise its extension"})
	}
	if doubleExt.MatchString(base) {
		out = append(out, Finding{"Heuristic.Name.DoubleExtension", 50, "executable disguised with a double extension"})
		if ft.IsExecutable() || ft == TypeLNK {
			out = append(out, Finding{"Heuristic.Name.DisguisedExecutable", 50, "content confirms the file really is an executable/shortcut"})
		}
	}
	if ft == TypePE && docExts[path.Ext(base)] {
		out = append(out, Finding{"Heuristic.Name.Masquerade", 60, "Windows executable disguised as a document/media file"})
	}
	return out
}

// Analyze runs every heuristic applicable to data and returns findings and
// any embedded objects that should be scanned recursively. Archive formats
// are unpacked by the caller; Analyze only inspects content.
func Analyze(name string, data []byte, ft FileType) ([]Finding, []Child) {
	if IsEICAR(data) {
		return []Finding{{"EICAR-Test-File", 100, "EICAR anti-malware test file"}}, nil
	}
	out := NameFindings(name, ft)
	var children []Child

	switch ft {
	case TypePE:
		out = append(out, analyzePE(data)...)
		out = append(out, analyzeBinaryStrings(data)...)
	case TypeELF, TypeMachO:
		if ft == TypeELF {
			out = append(out, analyzeELF(data)...)
		}
		out = append(out, analyzeBinaryStrings(data)...)
	case TypeOLE:
		out = append(out, analyzeOLE(data)...)
	case TypePDF:
		f, c := analyzePDF(data)
		out = append(out, f...)
		children = c
	case TypeRTF:
		out = append(out, analyzeRTF(data)...)
	case TypeLNK:
		out = append(out, analyzeLNK(data)...)
	case TypeText:
		out = append(out, analyzeText(name, data)...)
	case TypeUnknown:
		// Unknown binary blobs may still carry VBA (ActiveMime/MHT) payloads.
		out = append(out, analyzeVBA(ExtractVBA(data))...)
	}
	return dedupe(out), children
}

func analyzeText(name string, data []byte) []Finding {
	txt := TextContent(data)
	if len(txt) > maxTextAnalysis {
		txt = txt[:maxTextAnalysis]
	}
	lower := asciiLower(txt)
	out := evalIndicators(scriptIndicators, lower)
	out = append(out, analyzeOOXMLPart(name, lower)...)
	// Exported VBA modules (.bas/.cls) or macros embedded as plain text.
	if bytes.Contains(lower, []byte("attribute vb_name")) {
		out = append(out, analyzeVBA([]string{string(txt)})...)
	}
	// Base64-encoded executables inside scripts/HTML (HTML smuggling, droppers).
	if bytes.Contains(txt, []byte("TVqQAAMAAAAEAAAA")) || bytes.Contains(txt, []byte("TVpQAAIAAAAEAA8A")) {
		out = append(out, Finding{"Heuristic.Script.EmbeddedPE", 50, "contains a base64-encoded Windows executable"})
	}
	if bytes.Contains(lower, []byte("createobjecturl")) && bytes.Contains(lower, []byte("atob(")) &&
		(bytes.Contains(lower, []byte(".download")) || bytes.Contains(lower, []byte("mssaveoropenblob"))) {
		out = append(out, Finding{"Heuristic.HTML.Smuggling", 40, "assembles and downloads a file client-side (HTML smuggling)"})
	}
	return out
}

func dedupe(in []Finding) []Finding {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, f := range in {
		if f.Score <= 0 || seen[f.Name] {
			continue
		}
		seen[f.Name] = true
		out = append(out, f)
	}
	return out
}

// Score sums finding scores.
func Score(fs []Finding) int {
	s := 0
	for _, f := range fs {
		s += f.Score
	}
	return s
}
