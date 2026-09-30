package archive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

var (
	errNoPassword  = errors.New("encrypted with an unknown password")
	errUnsupported = errors.New("unsupported compression method")
)

const (
	methodWinZipAES = 99
	extraWinZipAES  = 0x9901
)

// decryptZipEntry returns the decrypted, decompressed content of an
// encrypted member, trying each password in turn. It supports traditional
// PKWARE encryption (ZipCrypto) and WinZip AES (AE-1/AE-2), with stored or
// deflated payloads. limit bounds the decompressed size read.
func decryptZipEntry(f *zip.File, passwords []string, limit int64) ([]byte, bool, error) {
	rr, err := f.OpenRaw()
	if err != nil {
		return nil, false, err
	}
	raw, err := io.ReadAll(rr)
	if err != nil {
		return nil, false, err
	}
	if f.Method == methodWinZipAES {
		return decryptAES(f, raw, passwords, limit)
	}
	return decryptZipCrypto(f, raw, passwords, limit)
}

func decompress(method uint16, data []byte, limit int64) ([]byte, bool, error) {
	var rd io.Reader
	switch method {
	case zip.Store:
		rd = bytes.NewReader(data)
	case zip.Deflate:
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		rd = fr
	default:
		return nil, false, errUnsupported
	}
	out, err := io.ReadAll(io.LimitReader(rd, limit+1))
	over := int64(len(out)) > limit
	if over {
		out = out[:limit]
		err = nil
	}
	return out, over, err
}

// --- ZipCrypto (APPNOTE 6.1) ---

type zipCryptoKeys [3]uint32

func (k *zipCryptoKeys) update(b byte) {
	k[0] = crc32.IEEETable[byte(k[0])^b] ^ (k[0] >> 8)
	k[1] = (k[1]+(k[0]&0xff))*134775813 + 1
	k[2] = crc32.IEEETable[byte(k[2])^byte(k[1]>>24)] ^ (k[2] >> 8)
}

func (k *zipCryptoKeys) decryptByte(c byte) byte {
	t := uint16(k[2] | 2)
	p := c ^ byte((uint32(t)*uint32(t^1))>>8)
	k.update(p)
	return p
}

func decryptZipCrypto(f *zip.File, raw []byte, passwords []string, limit int64) ([]byte, bool, error) {
	if len(raw) < 12 {
		return nil, false, errors.New("truncated encryption header")
	}
	crcCheck := byte(f.CRC32 >> 24)
	timeCheck := byte(f.ModifiedTime >> 8) //nolint:staticcheck // DOS time is what the check byte uses
	for _, pw := range passwords {
		k := zipCryptoKeys{0x12345678, 0x23456789, 0x34567890}
		for i := 0; i < len(pw); i++ {
			k.update(pw[i])
		}
		var last byte
		for i := 0; i < 12; i++ {
			last = k.decryptByte(raw[i])
		}
		if last != crcCheck && last != timeCheck {
			continue
		}
		plain := make([]byte, len(raw)-12)
		for i, c := range raw[12:] {
			plain[i] = k.decryptByte(c)
		}
		out, over, err := decompress(f.Method, plain, limit)
		if errors.Is(err, errUnsupported) {
			return nil, false, err
		}
		// The check byte gives a 1/256 false-accept rate; the CRC confirms.
		if err != nil || (!over && crc32.ChecksumIEEE(out) != f.CRC32) {
			continue
		}
		return out, over, nil
	}
	return nil, false, errNoPassword
}

// --- WinZip AES (AE-1 / AE-2) ---

func decryptAES(f *zip.File, raw []byte, passwords []string, limit int64) ([]byte, bool, error) {
	strength, method, version, ok := parseAESExtra(f.Extra)
	if !ok {
		return nil, false, errors.New("missing WinZip AES extra field")
	}
	keyLen := map[byte]int{1: 16, 2: 24, 3: 32}[strength]
	if keyLen == 0 {
		return nil, false, errors.New("invalid AES strength")
	}
	saltLen := keyLen / 2
	if len(raw) < saltLen+2+10 {
		return nil, false, errors.New("truncated AES data")
	}
	salt, pv := raw[:saltLen], raw[saltLen:saltLen+2]
	enc, auth := raw[saltLen+2:len(raw)-10], raw[len(raw)-10:]
	for _, pw := range passwords {
		dk, err := pbkdf2.Key(sha1.New, pw, salt, 1000, 2*keyLen+2)
		if err != nil {
			return nil, false, err
		}
		if !bytes.Equal(dk[2*keyLen:], pv) {
			continue
		}
		mac := hmac.New(sha1.New, dk[keyLen:2*keyLen])
		mac.Write(enc)
		if !hmac.Equal(mac.Sum(nil)[:10], auth) {
			continue
		}
		block, err := aes.NewCipher(dk[:keyLen])
		if err != nil {
			return nil, false, err
		}
		plain := make([]byte, len(enc))
		// WinZip uses CTR mode with a little-endian counter starting at 1.
		var ctr, ks [16]byte
		for off := 0; off < len(enc); off += 16 {
			for i := 0; i < 16; i++ {
				ctr[i]++
				if ctr[i] != 0 {
					break
				}
			}
			block.Encrypt(ks[:], ctr[:])
			for i := off; i < min(off+16, len(enc)); i++ {
				plain[i] = enc[i] ^ ks[i-off]
			}
		}
		out, over, err := decompress(method, plain, limit)
		if err != nil {
			return nil, false, err
		}
		// AE-1 also carries a CRC; AE-2 zeroes it.
		if version == 1 && !over && crc32.ChecksumIEEE(out) != f.CRC32 {
			return nil, false, errors.New("CRC mismatch after AES decryption")
		}
		return out, over, nil
	}
	return nil, false, errNoPassword
}

func parseAESExtra(extra []byte) (strength byte, method uint16, version uint16, ok bool) {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra)
		size := int(binary.LittleEndian.Uint16(extra[2:]))
		if 4+size > len(extra) {
			return
		}
		data := extra[4 : 4+size]
		if tag == extraWinZipAES && size >= 7 && data[2] == 'A' && data[3] == 'E' {
			return data[4], binary.LittleEndian.Uint16(data[5:]), binary.LittleEndian.Uint16(data), true
		}
		extra = extra[4+size:]
	}
	return
}
