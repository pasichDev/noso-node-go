package crypto

import "strings"

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

// DecodeBase64 mirrors base64.DecodeStringBase64(s) in its default,
// non-strict (MIME) mode: characters outside the alphabet are skipped and
// decoding stops at the first '='. A trailing group of 2 or 3 characters
// yields 1 or 2 bytes, a single leftover character is dropped.
//
// UNVERIFIED: the FPC unit is not part of the source tree and fpc is not
// available, so this follows the documented MIME-mode behaviour.
func DecodeBase64(s string) []byte {
	var out []byte
	var acc uint32
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' {
			break
		}
		v := strings.IndexByte(b64Alphabet, c)
		if v < 0 {
			continue
		}
		acc = acc<<6 | uint32(v)
		n++
		if n == 4 {
			out = append(out, byte(acc>>16), byte(acc>>8), byte(acc))
			acc, n = 0, 0
		}
	}
	switch n {
	case 2:
		out = append(out, byte(acc>>4))
	case 3:
		out = append(out, byte(acc>>10), byte(acc>>2))
	}
	return out
}
