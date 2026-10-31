package crypto

import (
	"math/big"
	"strings"

	"github.com/pasichDev/noso-node-go/internal/codec"
)

// Alphabets from nosocrypto.pas:80-82.
const (
	HexAlphabet = "0123456789ABCDEF"
	B36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	B58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// Address type selectors (nosocrypto.pas:83-84).
const (
	AddTypeReg   = 0
	AddTypeMulti = 1
)

// ---- TBigInteger helpers (CryptoLib4Pascal ClpBigInteger.pas) ----

// bigFromSignedBytes mirrors TBigInteger.Create(bytes): the bytes are a
// big-endian TWO'S COMPLEMENT number. COMPAT: nosocrypto.pas:591 (B16ToB58)
// uses this signed constructor, so a hash whose top bit is set is treated
// as negative.
func bigFromSignedBytes(b []byte) *big.Int {
	v := new(big.Int).SetBytes(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	return v
}

// bigToByteArrayUnsigned mirrors TBigInteger.ToByteArrayUnsigned
// (ClpBigInteger.pas:4981-5105). Zero yields an empty slice, positive
// values their minimal big-endian bytes, and negative values the minimal
// two's complement encoding (BitLength+1 bits rounded up to bytes).
func bigToByteArrayUnsigned(v *big.Int) []byte {
	switch v.Sign() {
	case 0:
		return []byte{}
	case 1:
		return v.Bytes()
	}
	// BitLength of a negative number is the bit length of (-v-1).
	m := new(big.Int).Neg(v)
	m.Sub(m, big.NewInt(1))
	nBytes := (m.BitLen() + 1 + 7) / 8
	mod := new(big.Int).Lsh(big.NewInt(1), uint(8*nBytes))
	t := new(big.Int).Add(v, mod)
	out := t.Bytes()
	for len(out) < nBytes {
		out = append([]byte{0}, out...)
	}
	return out
}

// base58Encode mirrors TBase58.BitCoin.Encode (SbpBase58.pas:190-250):
// leading zero bytes become '1', empty input yields "".
func base58Encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	if zeros == len(b) {
		return strings.Repeat("1", zeros)
	}
	v := new(big.Int).SetBytes(b)
	return strings.Repeat("1", zeros) + encodeDigits(v, B58Alphabet)
}

// base58Decode mirrors TBase58.BitCoin.Decode (SbpBase58.pas:91-178): leading
// '1' characters become zero bytes; an invalid character raises in Pascal
// (ok=false here).
func base58Decode(s string) ([]byte, bool) {
	if len(s) == 0 {
		return nil, true
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	if zeros == len(s) {
		return make([]byte, zeros), true
	}
	v := new(big.Int)
	f := big.NewInt(58)
	for i := zeros; i < len(s); i++ {
		d := strings.IndexByte(B58Alphabet, s[i])
		if d < 0 {
			return nil, false
		}
		v.Mul(v, f)
		v.Add(v, big.NewInt(int64(d)))
	}
	return append(make([]byte, zeros), v.Bytes()...), true
}

// encodeDigits writes v (>0) in the given alphabet without leading zeros.
func encodeDigits(v *big.Int, alphabet string) string {
	if v.Sign() == 0 {
		return ""
	}
	base := big.NewInt(int64(len(alphabet)))
	n := new(big.Int).Set(v)
	r := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.QuoRem(n, base, r)
		out = append(out, alphabet[r.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// hexToBytes mirrors TConverters.ConvertHexStringToBytes for an even
// length string; ok=false where Pascal raises.
func hexToBytes(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		h := hexVal(s[2*i])
		l := hexVal(s[2*i+1])
		if h < 0 || l < 0 {
			return nil, false
		}
		out[i] = byte(h<<4 | l)
	}
	return out, true
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func upperHex(b []byte) string {
	const d = "0123456789ABCDEF"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i] = d[c>>4]
		out[2*i+1] = d[c&15]
	}
	return string(out)
}

// trimLeadingZeros mirrors TrimLeadingCeros (nosocrypto.pas:501-506).
func trimLeadingZeros(s string) string {
	r := codec.Trim(s)
	if len(r) > 0 && r[0] == '0' {
		r = strings.TrimLeft(r, "0")
	}
	return r
}

// B10ToB16 mirrors nosocrypto.pas:508-522.
func B10ToB16(s string) string {
	s = codec.Trim(s)
	if s == "" {
		return "0"
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return "0"
	}
	return trimLeadingZeros(upperHex(bigToByteArrayUnsigned(v)))
}

// B10ToB58 mirrors nosocrypto.pas:524-533. COMPAT: an unparsable decimal
// string raises in Pascal (uncaught); callers only ever pass IntToStr
// output, so "" is returned instead of aborting.
func B10ToB58(s string) string {
	s = codec.Trim(s)
	if s == "" {
		return "1"
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return ""
	}
	return base58Encode(bigToByteArrayUnsigned(v))
}

// B16ToB10 mirrors nosocrypto.pas:535-552.
func B16ToB10(hexs string) string {
	s := codec.Trim(hexs)
	if s == "" {
		return "0"
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, ok := hexToBytes(s)
	if !ok {
		return "0"
	}
	return new(big.Int).SetBytes(b).String()
}

// B16ToB36 mirrors nosocrypto.pas:554-573 with EncodeBaseN (lines 103-173).
// Leading zero bytes yield no leading zero digits (the numZeroes term is
// commented out in the Pascal source); an all-zero input yields one '0' per
// zero byte.
func B16ToB36(hexs string) string {
	s := codec.Trim(hexs)
	if s == "" || s == "0" {
		return "0"
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, ok := hexToBytes(s)
	if !ok {
		return "0"
	}
	nz := 0
	for nz < len(b) && b[nz] == 0 {
		nz++
	}
	if nz == len(b) {
		return strings.Repeat("0", nz)
	}
	return encodeDigits(new(big.Int).SetBytes(b), B36Alphabet)
}

// B16ToB58 mirrors nosocrypto.pas:575-592. COMPAT: the bytes are read as a
// signed two's complement integer (see bigFromSignedBytes).
func B16ToB58(hexs string) string {
	s := codec.Trim(hexs)
	if s == "" {
		return "1"
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	b, ok := hexToBytes(s)
	if !ok {
		return "1"
	}
	return base58Encode(bigToByteArrayUnsigned(bigFromSignedBytes(b)))
}

// B16ToB58Lite1_60 is identical to B16ToB58 (nosocrypto.pas:594-611).
func B16ToB58Lite1_60(hexs string) string { return B16ToB58(hexs) }

// B58ToB10 mirrors nosocrypto.pas:613-627.
func B58ToB10(s string) string {
	s = codec.Trim(s)
	if s == "" {
		return "0"
	}
	b, ok := base58Decode(s)
	if !ok {
		return "0"
	}
	return new(big.Int).SetBytes(b).String()
}

// B58ToB16 mirrors nosocrypto.pas:629-644.
func B58ToB16(s string) string {
	s = codec.Trim(s)
	if s == "" {
		return "0"
	}
	b, ok := base58Decode(s)
	if !ok {
		return "0"
	}
	return trimLeadingZeros(upperHex(new(big.Int).SetBytes(b).Bytes()))
}

// ChecksumBase58 mirrors nosocrypto.pas:646-654 (sum of alphabet indices,
// -1 for characters outside the alphabet because Pos returns 0).
func ChecksumBase58(s string) int {
	t := 0
	for i := 0; i < len(s); i++ {
		t += strings.IndexByte(B58Alphabet, s[i])
	}
	return t
}

// BMB58resumen mirrors nosocrypto.pas:679-689 (decimal string of the sum).
func BMB58resumen(s string) string { return codec.IntToStr(int64(ChecksumBase58(s))) }

// BMB58resumenNew mirrors nosocrypto.pas:664-675 (sum plus the length).
func BMB58resumenNew(s string) string {
	return codec.IntToStr(int64(ChecksumBase58(s) + len(s)))
}

// BMB58resumenInt mirrors nosocrypto.pas:692-702.
func BMB58resumenInt(s string) int { return ChecksumBase58(s) }

// IsValid58 mirrors nosocrypto.pas:205-214.
func IsValid58(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(B58Alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

// BMHexTo58 converts a hex string via the decimal "BigMaths" path
// (nosocrypto.pas:915-942). It is mathematically a plain unsigned base
// conversion with no leading zero digits.
func BMHexTo58(hexs string, alphabet int) string {
	a := B58Alphabet
	if alphabet == 36 {
		a = B36Alphabet
	}
	v, ok := new(big.Int).SetString(strings.ToUpper(hexs), 16)
	if !ok {
		return ""
	}
	return encodeDigits(v, a[:alphabet])
}

// BMDecTo58 mirrors nosocrypto.pas:945-969.
func BMDecTo58(dec string) string {
	v, ok := new(big.Int).SetString(dec, 10)
	if !ok || v.Sign() < 0 {
		return ""
	}
	return encodeDigits(v, B58Alphabet)
}

// BMDecToHex mirrors nosocrypto.pas:972-996.
func BMDecToHex(dec string) string {
	v, ok := new(big.Int).SetString(dec, 10)
	if !ok || v.Sign() < 0 {
		return ""
	}
	return encodeDigits(v, HexAlphabet)
}

// BMHexToDec mirrors nosocrypto.pas:860-886.
func BMHexToDec(hexs string) string {
	if hexs == "" {
		return "0"
	}
	v, ok := new(big.Int).SetString(strings.ToUpper(hexs), 16)
	if !ok {
		return "0"
	}
	return v.String()
}

// BM58ToDec mirrors nosocrypto.pas:888-912 (no leading-zero compression).
func BM58ToDec(s string) string {
	v := new(big.Int)
	for i := 0; i < len(s); i++ {
		d := strings.IndexByte(B58Alphabet, s[i])
		v.Mul(v, big.NewInt(58))
		v.Add(v, big.NewInt(int64(d)))
	}
	return v.String()
}

// ClearLeadingCeros mirrors nosocrypto.pas:711-725.
func ClearLeadingCeros(n string) string {
	if n == "" {
		return "0"
	}
	neg := 0
	if n[0] == '-' {
		neg = 1
	}
	var r []byte
	for i := neg; i < len(n); i++ {
		if n[i] != '0' || len(r) > 0 {
			r = append(r, n[i])
		}
	}
	res := string(r)
	if res == "" {
		res = "0"
	}
	if neg == 1 && res != "0" {
		res = "-" + res
	}
	return res
}

// BMAdicion, BMMultiplicar, BMExponente and BMDividir keep the decimal
// string big-math contract of nosocrypto.pas:728-857 for unsigned decimal
// operands.
func BMAdicion(a, b string) string {
	x, ok1 := new(big.Int).SetString(a, 10)
	y, ok2 := new(big.Int).SetString(b, 10)
	if !ok1 || !ok2 {
		return ""
	}
	r := x.Add(x, y).String()
	// The Pascal routine pads to the longer operand and keeps leading zeros.
	if len(a) > len(r) || len(b) > len(r) {
		l := len(a)
		if len(b) > l {
			l = len(b)
		}
		r = strings.Repeat("0", l-len(r)) + r
	}
	return r
}

// BMMultiplicar returns the decimal product (leading zeros are not
// cleared, matching the commented ClearLeadingCeros at line 814, but for
// valid operands the product has none).
func BMMultiplicar(a, b string) string {
	x, ok1 := new(big.Int).SetString(a, 10)
	y, ok2 := new(big.Int).SetString(b, 10)
	if !ok1 || !ok2 {
		return ""
	}
	return x.Mul(x, y).String()
}

// BMExponente mirrors nosocrypto.pas:843-857.
func BMExponente(a, b string) string {
	switch b {
	case "1":
		return a
	case "0":
		return "1"
	}
	e, ok := codec.StrToInt(b)
	if !ok {
		return ""
	}
	r := a
	for i := int32(2); i <= e; i++ {
		r = BMMultiplicar(r, a)
	}
	return r
}

// DivResult is the quotient and remainder of BMDividir.
type DivResult struct{ Quotient, Remainder string }

// BMDividir divides a decimal string by a (Int64) divisor via schoolbook
// long division like nosocrypto.pas:818-840.
func BMDividir(num, div string) DivResult {
	d, ok := codec.StrToInt64(div)
	if !ok || d == 0 {
		return DivResult{}
	}
	var q []byte
	step := ""
	for i := 0; i < len(num); i++ {
		step += string(num[i])
		sv, _ := codec.StrToInt64(step)
		if sv >= d {
			q = append(q, []byte(codec.IntToStr(sv/d))...)
			step = codec.IntToStr(sv % d)
		} else {
			q = append(q, '0')
		}
	}
	return DivResult{ClearLeadingCeros(string(q)), ClearLeadingCeros(step)}
}
