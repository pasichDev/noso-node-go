package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strings"
)

// ChainID separates signatures of this network from any other use of the
// same keys. FIX(H-07, L-05).
//
// This is the default. A network made by `nosod init-network` has its own
// random chain id in its network file, and the orders of that network are
// signed under it (FIX(F-18)).
const ChainID = "noso-mainnet-v1"

// Canonical builds the preimage of a signature under the default chain id.
func Canonical(domain string, fields ...string) []byte {
	return CanonicalFor(ChainID, domain, fields...)
}

// CanonicalFor builds the preimage of a signature: a tag, the chain id, a
// domain and every field with a 4 byte big-endian length prefix, so no two
// different field lists produce the same bytes.
// FIX(H-07): the original signed concatenated text without separators and
// without several fields (mpprotocol.pas:762,792,973,1016).
func CanonicalFor(chain, domain string, fields ...string) []byte {
	var b []byte
	put := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b = append(b, l[:]...)
		b = append(b, s...)
	}
	put("NOSO-SIG-v1")
	put(chain)
	put(domain)
	for _, f := range fields {
		put(f)
	}
	return b
}

// SignCanonical signs SHA-256 of the canonical message with a Base64
// private key (low-S, DER, Base64). FIX(H-08): the raw bytes are signed; the
// original ran the text through a lenient Base64 decoder first
// (nosocrypto.pas:223).
func SignCanonical(privB64, domain string, fields ...string) string {
	return SignCanonicalFor(ChainID, privB64, domain, fields...)
}

// SignCanonicalFor is SignCanonical under an explicit chain id.
func SignCanonicalFor(chain, privB64, domain string, fields ...string) string {
	d := new(big.Int).SetBytes(DecodeBase64Lenient(privB64)) // legacy key text
	h := sha256.Sum256(CanonicalFor(chain, domain, fields...))
	sig, ok := ecdsaSignDigest(h[:], d)
	if !ok {
		return ""
	}
	return EncodeBase64(sig)
}

// VerifyCanonical checks a signature made by SignCanonical. Key and signature
// must be canonical Base64 and the signature canonical low-S DER: exactly one
// text verifies per (key, message, R, S).
func VerifyCanonical(pubB64, sigB64, domain string, fields ...string) bool {
	return VerifyCanonicalFor(ChainID, pubB64, sigB64, domain, fields...)
}

// VerifyCanonicalFor is VerifyCanonical under an explicit chain id.
func VerifyCanonicalFor(chain, pubB64, sigB64, domain string, fields ...string) bool {
	pub, ok := DecodeBase64Strict(pubB64)
	if !ok {
		return false
	}
	sig, ok := DecodeBase64Strict(sigB64)
	if !ok {
		return false
	}
	pt, ok := decodePoint(pub)
	if !ok {
		return false
	}
	h := sha256.Sum256(CanonicalFor(chain, domain, fields...))
	return ecdsaVerifyDigest(h[:], sig, pt)
}

// Certificates ---------------------------------------------------------------

// GetCertificate returns an ownership certificate for an address. FIX(L-05):
// the signature covers an audience and a verifier supplied nonce, and the
// useless XOR layer of the original (nosocrypto.pas:375) is gone. Fields must
// not contain ':'.
func GetCertificate(pub, priv, audience, nonce, curTime string) string {
	for _, f := range []string{audience, nonce, curTime} {
		if strings.ContainsRune(f, ':') {
			return ""
		}
	}
	addr := GetAddressFromPublicKey(pub, 0)
	sig := SignCanonical(priv, "CERT1", addr, audience, nonce, curTime)
	if sig == "" {
		return ""
	}
	return "C2:" + pub + ":" + curTime + ":" + audience + ":" + nonce + ":" + sig
}

// CheckCertificate verifies a certificate for the expected audience and
// nonce; it returns the address and signing time or "".
func CheckCertificate(cert, audience, nonce string) (addr, stamp string) {
	p := strings.Split(cert, ":")
	if len(p) != 6 || p[0] != "C2" || p[3] != audience || p[4] != nonce {
		return "", ""
	}
	a := GetAddressFromPublicKey(p[1], 0)
	if a == "" || !VerifyCanonical(p[1], p[5], "CERT1", a, audience, nonce, p[2]) {
		return "", ""
	}
	return a, p[2]
}
