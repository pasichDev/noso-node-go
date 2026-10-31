package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strings"
)

// ChainID separates signatures of this network from any other use of the
// same keys. FIX(H-07, L-05).
const ChainID = "noso-mainnet-v1"

// Canonical builds the preimage of a signature: a tag, the chain id, a
// domain and every field with a 4 byte big-endian length prefix, so no two
// different field lists produce the same bytes.
// FIX(H-07): the original signed concatenated text without separators and
// without several fields (mpprotocol.pas:762,792,973,1016).
func Canonical(domain string, fields ...string) []byte {
	var b []byte
	put := func(s string) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		b = append(b, l[:]...)
		b = append(b, s...)
	}
	put("NOSO-SIG-v1")
	put(ChainID)
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
	d := new(big.Int).SetBytes(DecodeBase64(privB64))
	h := sha256.Sum256(Canonical(domain, fields...))
	sig, ok := ecdsaSignDigest(h[:], d)
	if !ok {
		return ""
	}
	return EncodeBase64(sig)
}

// VerifyCanonical checks a signature made by SignCanonical.
func VerifyCanonical(pubB64, sigB64, domain string, fields ...string) bool {
	pt, ok := decodePoint(DecodeBase64(pubB64))
	if !ok {
		return false
	}
	h := sha256.Sum256(Canonical(domain, fields...))
	return ecdsaVerifyDigest(h[:], DecodeBase64(sigB64), pt)
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
