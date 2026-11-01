package crypto

import (
	"encoding/base64"
	"strings"
)

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// EncodeBase64 mirrors base64.EncodeStringBase64 of Free Pascal: standard
// alphabet with '=' padding and no line breaks.
func EncodeBase64(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3; j++ {
			v <<= 8
			if i+j < len(b) {
				v |= uint32(b[i+j])
				n++
			}
		}
		sb.WriteByte(b64Alphabet[v>>18&63])
		sb.WriteByte(b64Alphabet[v>>12&63])
		if n > 1 {
			sb.WriteByte(b64Alphabet[v>>6&63])
		} else {
			sb.WriteByte('=')
		}
		if n > 2 {
			sb.WriteByte(b64Alphabet[v&63])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// b64Dec is DecTable of fpc base64.pp: value 0-63, b64PC for '=' and b64NA
// for every other byte.
const (
	b64NA = 85
	b64PC = 255
)

func b64Val(c byte) byte {
	if c == '=' {
		return b64PC
	}
	if v := strings.IndexByte(b64Alphabet, c); v >= 0 {
		return byte(v)
	}
	return b64NA
}

// DecodeBase64Lenient reproduces base64.DecodeStringBase64(s) of FPC 3.2.x in its
// default MIME mode, statement by statement from fcl-base base64.pp
// (DecodeStringBase64, TBase64DecodingStream.GetSize and .Read): the input is
// first padded with '=' to a multiple of 4 (counting every byte, junk
// included); the output size comes from GetSize, which counts alphabet
// characters up to the first '=' (scanning in 1024 byte chunks, like the
// original); the bytes then come from Read, which skips characters outside
// the alphabet and ends a block at the first '='. Examples derived by hand:
// "QUJDQUI*" gives "ABC" (the junk character leaves a trailing group that
// GetSize does not count), "QUI" gives "AB".
//
// LEGACY DATA ONLY (reading Pascal-era wallet key text). Never use it to
// verify or to compare text; use DecodeBase64Strict.
//
// Verification status: the statement-by-statement port was checked against
// the fcl-base source in fpc322/, not against a run (FPC is not installed on
// the build machine), so the hand-derived examples are the only executable
// evidence. One open point: if the computed size is 0, TStream.CopyFrom may
// call Seek on the decoder, which raises in FPC; here an empty result is
// returned.
func DecodeBase64Lenient(s string) []byte {
	if len(s) == 0 {
		return []byte{}
	}
	sd := s
	for len(sd)%4 > 0 {
		sd += "="
	}
	size := b64MimeSize(sd)
	return b64Read(sd, size)
}

// b64MimeSize is TBase64DecodingStream.GetSize in bdmMIME.
func b64MimeSize(sd string) int64 {
	var result int64
	var c byte
	for pos := 0; ; {
		end := pos + 1024
		if end > len(sd) {
			end = len(sd)
		}
		chunk := sd[pos:end]
		pos = end
		for i := 0; i < len(chunk); i++ {
			c = chunk[i]
			if c == '=' {
				break // leaves only the for loop; the repeat goes on
			}
			if b64Val(c) != b64NA {
				result++
			}
		}
		if len(chunk) == 0 {
			break
		}
	}
	if c == '=' {
		if result%4 <= 1 {
			return (result / 4) * 3
		}
		return (result/4)*3 + result%4 - 1
	}
	return (result / 4) * 3
}

// b64Read is one TBase64DecodingStream.Read(Count=size) in bdmMIME, after
// GetSize has set DecodedSize.
func b64Read(sd string, size int64) []byte {
	out := []byte{}
	decoded := size
	count := size
	var curPos int64
	if count > decoded-curPos {
		count = decoded - curPos
	}
	if count <= 0 {
		return out
	}
	var buf [3]byte
	bufPos := 3
	src := 0
	for {
		if bufPos > 2 {
			bufPos = 0
			var rb [4]byte
			ok := 0
			for ok < 4 {
				if src >= len(sd) { // HaveRead < ToRead: end of input
					break
				}
				b := b64Val(sd[src])
				src++
				if b != b64NA {
					rb[ok] = b
					ok++
				}
			}
			// positions ok..3 stay 0 (padded with zeros)
			end := func(n int64) {
				decoded = n
				if curPos+count > decoded {
					count = decoded - curPos
				}
			}
			switch {
			case ok == 0:
				end(curPos)
			case rb[0] == b64PC || rb[1] == b64PC:
				end(curPos)
			case rb[2] == b64PC:
				end(curPos + 1)
			case rb[3] == b64PC:
				end(curPos + 2)
			}
			buf[0] = byte(int(rb[0])<<2 | int(rb[1])>>4)
			buf[1] = byte((int(rb[1])&15)<<4 | int(rb[2])>>2)
			buf[2] = byte((int(rb[2])&3)<<6 | int(rb[3]))
		}
		if count <= 0 {
			break
		}
		out = append(out, buf[bufPos])
		bufPos++
		curPos++
		count--
	}
	return out
}

// DecodeBase64Strict is the decoder for everything that is verified or
// compared: signatures, public keys, certificates. It accepts exactly the text
// EncodeBase64 produces (standard alphabet, '=' padding, no junk, no
// whitespace, zero trailing bits), so one byte string has one text. The
// lenient decoder below skips bytes, which let a third party re-spell a signed
// object and change its hash without a key (re2 H-1).
func DecodeBase64Strict(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || EncodeBase64(b) != s { // the second test rejects CR/LF, which the stdlib skips
		return nil, false
	}
	return b, true
}
