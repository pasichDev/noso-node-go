// Package crypto implements the hashing, base conversion, key and address
// primitives of the Noso protocol, byte-compatible with nosocrypto.pas and
// mpsignerutils.pas of the Pascal node.
//
// All "string" arguments are treated as raw byte strings, exactly like the
// Pascal AnsiString values they mirror.
package crypto

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// SHA256String mirrors HashSha256String (nosocrypto.pas:177-180). HashLib's
// ToString yields upper-case hex.
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

// MD5String mirrors HashMD5String (nosocrypto.pas:189-192): upper-case hex.
func MD5String(s string) string {
	h := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// MD5OfEmpty is returned by HashMD5File when the file cannot be read
// (nosocrypto.pas:197).
const MD5OfEmpty = "D41D8CD98F00B204E9800998ECF8427E"

// MD5File mirrors HashMD5File (nosocrypto.pas:195-202). Unreadable file
// yields the MD5 of the empty string.
func MD5File(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return MD5OfEmpty
	}
	return MD5Bytes(b)
}

// MD5Bytes returns the upper-case hex MD5 of raw bytes.
func MD5Bytes(b []byte) string {
	h := md5.Sum(b)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}
