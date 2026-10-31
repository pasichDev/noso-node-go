package crypto

import (
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// KeyPair is the Noso key encoding: public = Base64(uncompressed point),
// private = Base64(minimal big-endian scalar) (mpsignerutils.pas:178-181).
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// GenerateKeyPair mirrors TSignerUtils.GenerateECKeyPair.
func GenerateKeyPair() KeyPair {
	for {
		d, err := rand.Int(rand.Reader, secpN)
		if err != nil {
			panic(err)
		}
		if d.Sign() == 0 {
			continue
		}
		pt := scalarMult(basePoint(), d)
		return KeyPair{
			PublicKey:  EncodeBase64(encodePoint(pt)),
			PrivateKey: EncodeBase64(d.Bytes()),
		}
	}
}

// GetStringSigned mirrors nosocrypto.pas:217-228. COMPAT: the message is
// first run through the lenient Base64 decoder (line 223), so a plain text
// message is signed as the bytes left after discarding every non-Base64
// character. Errors yield "".
func GetStringSigned(msg, privateKey string) string {
	d := new(big.Int).SetBytes(DecodeBase64(privateKey))
	sig, ok := ecdsaSignSHA1(DecodeBase64(msg), d)
	if !ok {
		return ""
	}
	return EncodeBase64(sig)
}

// VerifySignedString mirrors nosocrypto.pas:231-242, including the lenient
// Base64 decoding of the message (line 237).
func VerifySignedString(msg, sigB64, pubKey string) bool {
	pt, ok := decodePoint(DecodeBase64(pubKey))
	if !ok {
		return false
	}
	return ecdsaVerifySHA1(DecodeBase64(msg), DecodeBase64(sigB64), pt)
}

// GetAddressFromPublicKey mirrors nosocrypto.pas:245-258. COMPAT: the hash
// input is the Base64 TEXT of the public key, and RIPEMD-160 is taken over
// the upper-case hex TEXT of the SHA-256. An addType other than 0/1 returns
// "" (uninitialised Result).
func GetAddressFromPublicKey(pub string, addType int) string {
	h1 := RIPEMD160String(SHA256String(pub))
	body := BMHexTo58(h1, 58)
	clave := BMDecTo58(BMB58resumen(body))
	switch addType {
	case AddTypeReg:
		return "N" + body + clave
	case AddTypeMulti:
		return "M" + body + clave
	}
	return ""
}

// NewGetAddressFromPublicKey mirrors nosocrypto.pas:260-272 (the B16ToB58
// variant, unused by the node paths but part of the unit).
func NewGetAddressFromPublicKey(pub string) string {
	h1 := B16ToB58(RIPEMD160String(SHA256String(pub)))
	return "N" + h1 + B10ToB58(BMB58resumen(h1))
}

// IsValidHashAddress mirrors nosocrypto.pas:327-342. COMPAT: the checksum
// is implicitly required to be exactly 2 characters long because the body
// is copy(addr,2,len-3).
func IsValidHashAddress(addr string) bool {
	if len(addr) < 1 {
		return false
	}
	if len(addr) > 20 && (addr[0] == 'N' || addr[0] == 'M') {
		orig := codec.Copy(addr, 2, len(addr)-3)
		if IsValid58(orig) && addr[:1]+orig+B10ToB58(BMB58resumen(orig)) == addr {
			return true
		}
	}
	return false
}

// GetTransferHash mirrors nosocrypto.pas:345-352.
func GetTransferHash(text string) string {
	r := B16ToB58(SHA256String(text))
	return "tR" + r + B10ToB58(BMB58resumen(r))
}

// GetOrderHash mirrors nosocrypto.pas:355-359.
func GetOrderHash(text string) string { return "OR" + B16ToB36(SHA256String(text)) }

// XorEncode mirrors StrUtils.XorEncode: lower-case hex of key-xored bytes.
func XorEncode(key, src string) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		if len(key) > 0 {
			c ^= key[i%len(key)]
		}
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

// XorDecode mirrors StrUtils.XorDecode; an invalid hex pair decodes as ' '.
func XorDecode(key, src string) string {
	out := make([]byte, 0, len(src)/2)
	for i := 0; i < len(src)/2; i++ {
		c := byte(' ')
		h, l := hexVal(src[2*i]), hexVal(src[2*i+1])
		if h >= 0 && l >= 0 {
			c = byte(h<<4 | l)
		}
		if len(key) > 0 {
			c ^= key[i%len(key)]
		}
		out = append(out, c)
	}
	return string(out)
}

// GetCertificateChecksum mirrors nosocrypto.pas:656-661.
func GetCertificateChecksum(cert string) string {
	r := B10ToB58(BMB58resumenNew(cert))
	for len(r) < 3 {
		r = "1" + r
	}
	return r
}

// GetCertificate mirrors nosocrypto.pas:362-383.
func GetCertificate(pub, priv, curTime string) string {
	addr := GetAddressFromPublicKey(pub, 0)
	sig := GetStringSigned("OWN"+addr+curTime, priv)
	if sig == "" {
		return ""
	}
	cert := "OWN:" + pub + ":" + curTime + ":" + sig
	cert = strings.ToUpper(XorEncode(SHA256String("noso"), cert))
	r := B16ToB58("1" + cert)
	return r + GetCertificateChecksum(r)
}

// CheckCertificate mirrors nosocrypto.pas:386-416. It returns the address
// and the certificate time, or "" on any failure.
func CheckCertificate(cert string) (addr, stamp string) {
	if len(cert) < 3 {
		return "", ""
	}
	sum := cert[len(cert)-3:]
	cert = cert[:len(cert)-3]
	if sum != GetCertificateChecksum(cert) {
		return "", ""
	}
	hexs := B58ToB16(cert)
	if len(hexs) < 1 {
		return "", ""
	}
	hexs = hexs[1:]
	plain := XorDecode(SHA256String("noso"), hexs)
	parts := strings.Split(plain, ":")
	if len(parts) < 4 {
		return "", ""
	}
	a := GetAddressFromPublicKey(parts[1], 0)
	if VerifySignedString("OWN"+a+parts[2], parts[3], parts[1]) {
		return a, parts[2]
	}
	return "", ""
}

// CheckHashDiff mirrors nosocrypto.pas:419-438 (per-nibble absolute
// difference of two MD5 hex strings). Non-hex characters raise in Pascal;
// ok is false for them.
func CheckHashDiff(target, this string) (string, bool) {
	pad := func(s string) string {
		for len(s) < 32 {
			s += "\x00"
		}
		return s
	}
	target, this = pad(target), pad(this)
	var sb strings.Builder
	for i := 0; i < 32; i++ {
		a, b := hexVal(this[i]), hexVal(target[i])
		if a < 0 || b < 0 {
			return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", false
		}
		d := a - b
		if d < 0 {
			d = -d
		}
		sb.WriteByte("0123456789ABCDEF"[d])
	}
	return sb.String(), true
}

// GetMultiSource mirrors nosocrypto.pas:442-498 verbatim, including the
// insertion loop whose upper bound is fixed before inserting, which can
// duplicate entries. On failure the message is returned in ordered.
func GetMultiSource(source string, addsTotal int) (ordered string, ok bool) {
	loc := strings.ReplaceAll(source, ",", " ")
	var addrs []string
	existing := ""
	counter := 0
	this := ""
	for {
		this = codec.Parameter(loc, int64(counter))
		if this != "" {
			if strings.Contains(existing, this) {
				return "Duplicated address -> " + this, false
			}
			existing += "," + this
			if !IsValidHashAddress(this) {
				return "Invalid hash address -> " + this, false
			}
			if len(addrs) == 0 {
				addrs = append(addrs, this)
			} else {
				inserted := false
				n := len(addrs) // COMPAT: bound evaluated once (nosocrypto.pas:475)
				for c2 := 0; c2 < n; c2++ {
					if this < addrs[c2] {
						addrs = append(addrs, "")
						copy(addrs[c2+1:], addrs[c2:])
						addrs[c2] = this
						inserted = true
					}
				}
				if !inserted {
					addrs = append(addrs, this)
				}
			}
		}
		counter++
		if this == "" || counter == addsTotal {
			break
		}
	}
	msg := ""
	if len(addrs) != addsTotal {
		msg = "Wrong addresses count " + codec.IntToStr(int64(len(addrs))) + "/" + codec.IntToStr(int64(addsTotal))
	}
	if msg == "" {
		return strings.Join(addrs, ","), true
	}
	return msg, false
}
