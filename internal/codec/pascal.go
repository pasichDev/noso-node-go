package codec

import "encoding/binary"

// Free Pascal packed-record helpers. Every multi-byte integer is
// little-endian (x86-64 / AArch64 Linux, Windows and macOS builds of the
// original node). A ShortString[N] occupies N+1 bytes: a length byte
// followed by N character bytes.

// GetShort reads a ShortString[max] stored at b[0:max+1]. A corrupt length
// byte larger than max is clamped.
func GetShort(b []byte, max int) string {
	n := int(b[0])
	if n > max {
		n = max
	}
	return string(b[1 : 1+n])
}

// PutShort assigns s to the ShortString[max] at b[0:max+1] the way an
// FPC assignment does: the string is truncated to max characters, the length
// byte and the characters are written, and the bytes after the new end are
// left untouched (so a record that was loaded from disk keeps whatever
// trailing bytes it had).
func PutShort(b []byte, max int, s string) {
	if len(s) > max {
		s = s[:max]
	}
	b[0] = byte(len(s))
	copy(b[1:], s)
}

// I32 reads a little-endian int32.
func I32(b []byte) int32 { return int32(binary.LittleEndian.Uint32(b)) }

// I64 reads a little-endian int64.
func I64(b []byte) int64 { return int64(binary.LittleEndian.Uint64(b)) }

// PutI32 writes a little-endian int32.
func PutI32(b []byte, v int32) { binary.LittleEndian.PutUint32(b, uint32(v)) }

// PutI64 writes a little-endian int64.
func PutI64(b []byte, v int64) { binary.LittleEndian.PutUint64(b, uint64(v)) }

// Truncate mirrors the effect of assigning s to a ShortString[max].
func Truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
