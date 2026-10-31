// Package crypto implements the hashing, base conversion, key and address
// primitives of the Noso protocol. Identity formats of addresses are those
// of nosocrypto.pas; signatures, file identities and certificates were
// replaced as described in docs/compatibility.md.
package crypto

import (
	"crypto/md5" //nolint:gosec // only for the md5 console command
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// SHA256String mirrors HashSha256String (nosocrypto.pas:177-180): upper-case hex.
func SHA256String(s string) string {
	h := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// RIPEMD160String mirrors HashMD160String (nosocrypto.pas:183-186): the
// input is the string itself (typically an upper-case hex string).
func RIPEMD160String(s string) string {
	h := ripemd160Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// MD5Hex returns the real MD5, kept for the `md5` console command only.
func MD5Hex(s string) string {
	h := md5.Sum([]byte(s)) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// IDHash is the identity hash of files, blocks and state: the first 32 hex
// characters (128 bits) of SHA-256, upper case. FIX(M-13): the original used
// MD5 (nosocrypto.pas:189-202) for the same purpose; 32 characters keep the
// ShortString[32] header fields unchanged.
func IDHash(s string) string { return IDHashBytes([]byte(s)) }

// IDHashBytes is IDHash for raw bytes.
func IDHashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(h[:16]))
}

// IDHashOfEmpty is the hash of no bytes, returned for unreadable files like
// HashMD5File's fallback (nosocrypto.pas:197).
var IDHashOfEmpty = IDHashBytes(nil)

// IDHashFile is IDHash of a file's content; an unreadable file yields
// IDHashOfEmpty.
func IDHashFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return IDHashOfEmpty
	}
	return IDHashBytes(b)
}
