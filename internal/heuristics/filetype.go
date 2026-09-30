// Package heuristics contains FileGate's static-analysis detection engine.
package heuristics

import (
	"bytes"
	"unicode/utf8"
)

// FileType is a coarse content classification based on magic bytes.
type FileType string

const (
	TypeUnknown FileType = "unknown"
	TypeText    FileType = "text"
	TypePE      FileType = "pe"
	TypeELF     FileType = "elf"
	TypeMachO   FileType = "macho"
	TypeOLE     FileType = "ole" // legacy Office / MSI / vbaProject.bin
	TypePDF     FileType = "pdf"
	TypeRTF     FileType = "rtf"
	TypeLNK     FileType = "lnk"
	TypeZip     FileType = "zip"
	TypeGzip    FileType = "gzip"
	TypeBzip2   FileType = "bzip2"
	TypeXZ      FileType = "xz"
	TypeTar     FileType = "tar"
	Type7z      FileType = "7z"
	TypeRAR     FileType = "rar"
	TypeISO     FileType = "iso"
	TypeCAB     FileType = "cab"
	TypeImage   FileType = "image"
)

var (
	magicOLE  = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	magicLNK  = []byte{0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00}
	magic7z   = []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}
	magicXZ   = []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	magicRAR  = []byte("Rar!\x1a\x07")
	magicCAB  = []byte("MSCF\x00\x00\x00\x00")
	magicELF  = []byte("\x7fELF")
	magicPDF  = []byte("%PDF-")
	magicRTF  = []byte("{\\rt")
	magicPNG  = []byte("\x89PNG\r\n\x1a\n")
	magicJPEG = []byte{0xFF, 0xD8, 0xFF}
	magicGIF  = []byte("GIF8")
)

// Detect classifies data by its content.
func Detect(data []byte) FileType {
	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return TypePE
	case bytes.HasPrefix(data, magicELF):
		return TypeELF
	case isMachO(data):
		return TypeMachO
	case bytes.HasPrefix(data, magicOLE):
		return TypeOLE
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return TypeZip
	case len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8:
		return TypeGzip
	case bytes.HasPrefix(data, []byte("BZh")) && len(data) > 3 && data[3] >= '1' && data[3] <= '9':
		return TypeBzip2
	case bytes.HasPrefix(data, magicXZ):
		return TypeXZ
	case bytes.HasPrefix(data, magic7z):
		return Type7z
	case bytes.HasPrefix(data, magicRAR):
		return TypeRAR
	case bytes.HasPrefix(data, magicCAB):
		return TypeCAB
	case bytes.HasPrefix(data, magicLNK):
		return TypeLNK
	case bytes.HasPrefix(data, magicRTF):
		return TypeRTF
	case bytes.HasPrefix(data, magicPNG), bytes.HasPrefix(data, magicJPEG), bytes.HasPrefix(data, magicGIF):
		return TypeImage
	case len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")):
		return TypeTar
	case len(data) > 0x8006 && bytes.Equal(data[0x8001:0x8006], []byte("CD001")):
		return TypeISO
	}
	// PDF headers may be preceded by junk (readers accept it within 1 KiB).
	head := data
	if len(head) > 1024 {
		head = head[:1024]
	}
	if bytes.Contains(head, magicPDF) {
		return TypePDF
	}
	if IsText(data) {
		return TypeText
	}
	return TypeUnknown
}

func isMachO(d []byte) bool {
	if len(d) < 4 {
		return false
	}
	m := uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
	switch m {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
		return true
	case 0xCAFEBABE: // fat binary; also Java class files, disambiguate by arch count
		return len(d) >= 8 && d[4] == 0 && d[5] == 0 && d[6] == 0 && d[7] > 0 && d[7] < 20
	}
	return false
}

// IsText reports whether the start of data looks like human-readable text
// (UTF-8/ASCII, or UTF-16 with BOM).
func IsText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		return true
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	bad := 0
	for i := 0; i < len(sample); {
		r, size := utf8.DecodeRune(sample[i:])
		if r == 0 {
			return false
		}
		if r == utf8.RuneError && size == 1 {
			// tolerate a truncated rune at the end of the sample
			if len(sample)-i < 4 && len(sample) < len(data) {
				break
			}
			bad++
		} else if r < 0x20 && r != '\n' && r != '\r' && r != '\t' && r != '\f' && r != 0x1b {
			bad++
		}
		i += size
	}
	return bad*20 < len(sample) // < 5% non-text
}

// TextContent returns data as searchable text, decoding UTF-16 if needed.
func TextContent(data []byte) []byte {
	if len(data) >= 2 {
		if data[0] == 0xFF && data[1] == 0xFE {
			return utf16ToASCII(data[2:], false)
		}
		if data[0] == 0xFE && data[1] == 0xFF {
			return utf16ToASCII(data[2:], true)
		}
	}
	return data
}

// utf16ToASCII narrows UTF-16 to single bytes, which is sufficient for
// matching ASCII indicators.
func utf16ToASCII(b []byte, bigEndian bool) []byte {
	out := make([]byte, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		lo, hi := b[i], b[i+1]
		if bigEndian {
			lo, hi = hi, lo
		}
		if hi == 0 {
			out = append(out, lo)
		} else {
			out = append(out, '?')
		}
	}
	return out
}

// IsArchive reports whether FileGate can unpack this type.
func (t FileType) IsArchive() bool {
	switch t {
	case TypeZip, TypeGzip, TypeBzip2, TypeXZ, TypeTar:
		return true
	}
	return false
}

// IsExecutable reports whether the type is native code.
func (t FileType) IsExecutable() bool {
	return t == TypePE || t == TypeELF || t == TypeMachO
}

var lowerTable = func() (t [256]byte) {
	for i := range t {
		t[i] = byte(i)
		if i >= 'A' && i <= 'Z' {
			t[i] = byte(i) + 32
		}
	}
	return
}()

// asciiLower lowercases ASCII letters only. Unlike bytes.ToLower it never
// takes the slow Unicode path on binary input and preserves length, so
// offsets stay aligned with the original data.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = lowerTable[c]
	}
	return out
}
