package heuristics

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"math"
	"strings"
)

// Entropy returns the Shannon entropy of b in bits per byte (0..8).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

var packerSections = map[string]string{
	"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
	".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".themida": "Themida",
	".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
	".enigma2": "Enigma", "pec2": "PECompact", "pecompact": "PECompact", ".nsp0": "NsPack",
	".nsp1": "NsPack", "nsp0": "NsPack", ".perplex": "Perplex", ".yp": "Y0da", ".packed": "generic",
	"kkrunchy": "kkrunchy", ".mew": "MEW", "fsg!": "FSG",
}

type apiCombo struct {
	name  string
	score int
	desc  string
	apis  [][]string // each group: at least one must be imported
}

var peAPICombos = []apiCombo{
	{"Heuristic.PE.ProcessInjection", 50, "imports the classic remote process injection API set",
		[][]string{{"virtualallocex", "ntallocatevirtualmemory"}, {"writeprocessmemory", "ntwritevirtualmemory"}, {"createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread", "setthreadcontext"}}},
	{"Heuristic.PE.ProcessHollowing", 50, "imports process hollowing APIs",
		[][]string{{"ntunmapviewofsection", "zwunmapviewofsection"}, {"setthreadcontext", "wow64setthreadcontext"}, {"resumethread"}}},
	{"Heuristic.PE.Keylogger", 35, "imports keyboard hooking/polling APIs",
		[][]string{{"setwindowshookexa", "setwindowshookexw"}, {"getasynckeystate", "getkeystate", "getkeyboardstate"}}},
	{"Heuristic.PE.Downloader", 20, "imports URL download-and-execute APIs",
		[][]string{{"urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw"}, {"shellexecutea", "shellexecutew", "winexec", "createprocessa", "createprocessw"}}},
	{"Heuristic.PE.CredentialAccess", 30, "reads process memory of other processes (e.g. LSASS dumping)",
		[][]string{{"minidumpwritedump"}, {"openprocess"}}},
	{"Heuristic.PE.AntiDebug", 10, "uses several anti-debugging checks",
		[][]string{{"isdebuggerpresent"}, {"checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"}}},
	{"Heuristic.PE.CryptoRansom", 25, "combines file enumeration with bulk encryption APIs",
		[][]string{{"findfirstfilew", "findfirstfileexw"}, {"cryptencrypt", "bcryptencrypt"}, {"movefileexw", "movefilew", "setfileattributesw"}}},
}

func analyzePE(data []byte) []Finding {
	var out []Finding
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		// "MZ" but unparsable PE: could be a DOS stub or a corrupted/trick file.
		if len(data) > 0x40 && bytes.Contains(data[:min(len(data), 1024)], []byte("PE\x00\x00")) {
			out = append(out, Finding{"Heuristic.PE.Malformed", 30, "malformed PE headers (anti-analysis)"})
		}
		return out
	}
	defer f.Close()

	// Packers and section anomalies.
	packers := map[string]bool{}
	highEntropyExec := 0
	var epSection *pe.Section
	var ep uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		ep = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		ep = oh.AddressOfEntryPoint
	}
	wx := false
	for _, s := range f.Sections {
		sn := strings.ToLower(strings.TrimRight(s.Name, "\x00"))
		if p, ok := packerSections[sn]; ok {
			packers[p] = true
		}
		const (
			memExec  = 0x20000000
			memWrite = 0x80000000
		)
		if s.Characteristics&memExec != 0 && s.Characteristics&memWrite != 0 {
			wx = true
		}
		if ep >= s.VirtualAddress && ep < s.VirtualAddress+max(s.VirtualSize, s.Size) {
			epSection = s
		}
		if s.Characteristics&memExec != 0 && s.Size > 1024 {
			if sd, err := s.Data(); err == nil && Entropy(sd) > 7.2 {
				highEntropyExec++
			}
		}
	}
	for p := range packers {
		out = append(out, Finding{"Heuristic.PE.Packer." + p, 20, "packed with " + p})
	}
	if bytes.Contains(data[:min(len(data), 4096)], []byte("UPX!")) && !packers["UPX"] {
		out = append(out, Finding{"Heuristic.PE.Packer.UPX", 20, "packed with UPX"})
	}
	if wx {
		out = append(out, Finding{"Heuristic.PE.WritableCode", 15, "section is both writable and executable"})
	}
	if highEntropyExec > 0 {
		out = append(out, Finding{"Heuristic.PE.EncryptedCode", 25, "executable section with near-random content (packed/encrypted)"})
	}
	if ep != 0 && epSection == nil && len(f.Sections) > 0 {
		out = append(out, Finding{"Heuristic.PE.EntryPointOutsideSections", 35, "entry point lies outside all sections"})
	} else if epSection != nil && len(f.Sections) > 1 && epSection == f.Sections[len(f.Sections)-1] &&
		!strings.HasPrefix(strings.ToLower(epSection.Name), ".text") {
		out = append(out, Finding{"Heuristic.PE.EntryPointLastSection", 20, "entry point in last section (appended stub)"})
	}

	// Imports.
	syms, _ := f.ImportedSymbols()
	imported := map[string]bool{}
	for _, s := range syms {
		fn := s
		if i := strings.IndexByte(s, ':'); i >= 0 {
			fn = s[:i]
		}
		imported[strings.ToLower(fn)] = true
	}
	for _, c := range peAPICombos {
		ok := true
		for _, group := range c.apis {
			hit := false
			for _, api := range group {
				if imported[api] {
					hit = true
					break
				}
			}
			if !hit {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, Finding{c.name, c.score, c.desc})
		}
	}
	isDotNet := imported["_corexemain"] || imported["_cordllmain"]
	if len(syms) > 0 && len(syms) <= 4 && highEntropyExec > 0 && !isDotNet {
		out = append(out, Finding{"Heuristic.PE.MinimalImports", 15, "very few imports with encrypted code (runtime unpacking)"})
	}

	// Overlay: large, high-entropy data appended after the last section.
	var end uint32
	for _, s := range f.Sections {
		if s.Offset+s.Size > end {
			end = s.Offset + s.Size
		}
	}
	if end > 0 && int(end) < len(data) {
		overlay := data[end:]
		if len(overlay) > 64*1024 && len(overlay) > len(data)/2 {
			if bytes.HasPrefix(overlay, []byte("MZ")) {
				out = append(out, Finding{"Heuristic.PE.EmbeddedExecutable", 30, "another executable appended to this one (dropper)"})
			}
		}
	}

	return out
}

func analyzeELF(data []byte) []Finding {
	var out []Finding
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return []Finding{{"Heuristic.ELF.Malformed", 25, "malformed ELF headers (anti-analysis)"}}
	}
	defer f.Close()
	if bytes.Contains(data[:min(len(data), 4096)], []byte("UPX!")) {
		out = append(out, Finding{"Heuristic.ELF.Packer.UPX", 20, "packed with UPX"})
	}
	if len(f.Sections) == 0 && f.Type == elf.ET_EXEC && len(data) > 16*1024 {
		out = append(out, Finding{"Heuristic.ELF.NoSections", 15, "section headers stripped"})
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Flags&elf.PF_W != 0 {
			out = append(out, Finding{"Heuristic.ELF.WritableCode", 15, "segment is both writable and executable"})
			break
		}
	}
	// Statically linked binaries with an interpreter-less, stripped layout and
	// high entropy are typical of packed IoT bots.
	if f.Type == elf.ET_EXEC && len(f.Sections) == 0 && Entropy(data) > 7.3 {
		out = append(out, Finding{"Heuristic.ELF.PackedStatic", 20, "stripped and highly compressed static binary"})
	}
	return out
}

func analyzeBinaryStrings(data []byte) []Finding {
	return evalIndicators(binaryIndicators, asciiLower(data))
}
