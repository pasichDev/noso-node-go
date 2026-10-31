package crypto

import (
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
)

// Vector from masterpaskalform.pas:582-583: AdminPubKey must derive ADMINHash
// through GetAddressFromPublicKey (nosocrypto.pas:245-258).
const (
	adminPub  = "BACo0LC7mWDn53orLANA2zKVSC1HfSe/jc/Ih7+cBQ1oh53Bu2Zo655WFmWnoKHEeaNflb1CR9WcfXuhmkKaY8Y="
	adminAddr = "N3DthVsfEUtqrgWFHTEB6F88xLkT3Df"
)

func TestAdminAddressDerivation(t *testing.T) {
	if got := GetAddressFromPublicKey(adminPub, AddTypeReg); got != adminAddr {
		t.Fatalf("got %s want %s", got, adminAddr)
	}
	if !IsValidHashAddress(adminAddr) {
		t.Fatal("admin address must validate")
	}
	if m := GetAddressFromPublicKey(adminPub, AddTypeMulti); m[0] != 'M' || m[1:] != adminAddr[1:] {
		t.Fatalf("multi %s", m)
	}
	if GetAddressFromPublicKey(adminPub, 2) != "" {
		t.Fatal("unknown type must be empty")
	}
}

func TestHashes(t *testing.T) {
	// SHA-256 and MD5 of "abc" are standard; HashLib prints upper-case.
	if SHA256String("abc") != "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" {
		t.Error("sha256")
	}
	if MD5Hex("abc") != "900150983CD24FB0D6963F7D28E17F72" {
		t.Error("md5")
	}
}

func TestSignedBigIntQuirk(t *testing.T) {
	// 0x80 0x01: signed value is -32767 (0x8001-0x10000); minimal two's
	// complement unsigned byte array is 80 01 again; no leading '1' chars.
	v := bigFromSignedBytes([]byte{0x80, 0x01})
	if v.Int64() != -32767 {
		t.Fatal(v)
	}
	if got := bigToByteArrayUnsigned(v); string(got) != "\x80\x01" {
		t.Fatalf("% x", got)
	}
	// 0xFF 0x80 is -128, minimal two's complement is the single byte 0x80:
	// the leading 0xFF byte is DROPPED (ClpBigInteger.pas BitLength+1 rule).
	v = bigFromSignedBytes([]byte{0xFF, 0x80})
	if got := bigToByteArrayUnsigned(v); string(got) != "\x80" {
		t.Fatalf("% x", got)
	}
	// Positive values lose leading zero bytes.
	if got := bigToByteArrayUnsigned(big.NewInt(0x0102)); string(got) != "\x01\x02" {
		t.Fatal("pos")
	}
	if len(bigToByteArrayUnsigned(big.NewInt(0))) != 0 {
		t.Fatal("zero")
	}
}

func TestB16ToB58VsReference(t *testing.T) {
	// For a positive top nibble B16ToB58 equals plain base58 of the bytes.
	hexs := "0A" + strings.Repeat("11", 31)
	b := hexToBytes(hexs)
	want := encodeDigits(new(big.Int).SetBytes(b), B58Alphabet)
	if got := B16ToB58(hexs); got != want {
		t.Fatalf("%s vs %s", got, want)
	}
	// Invalid hex does not raise in FPC (HexToBin stops at the first bad
	// character, the rest of the buffer stays 0; ClpConverters.pas:480-498,
	// classes/util.inc). Values derived from that source by hand.
	if B16ToB58("") != "1" || B16ToB58("zz") != "" {
		t.Error("defaults")
	}
	if got, want := B16ToB58("12zz"), B16ToB58("1200"); got != want {
		t.Errorf("12zz = %q want %q", got, want)
	}
	if B16ToB10("FFzz") != "65280" || B16ToB36("FFxx") != encodeDigits(big.NewInt(65280), B36Alphabet) {
		t.Errorf("FFzz %s %s", B16ToB10("FFzz"), B16ToB36("FFxx"))
	}
	if B16ToB10("1-2") != "1" || B16ToB10("FF-") != "15" { // odd length is padded before the dash is removed: "0FF" -> byte 0F
		t.Errorf("dash %s %s", B16ToB10("1-2"), B16ToB10("FF-"))
	}
}

func TestB16ToB36(t *testing.T) {
	if B16ToB36("0") != "0" || B16ToB36("") != "0" || B16ToB36("xx") != "0" {
		t.Error("defaults")
	}
	// 0x00FF = 255 = "73" in base 36; leading zero byte gives no digit.
	if got := B16ToB36("00FF"); got != "73" {
		t.Errorf("got %s", got)
	}
	if B16ToB36("0000") != "00" {
		t.Error("all zero bytes give one 0 per byte")
	}
}

func TestOrderAndTransferHashShape(t *testing.T) {
	oh := GetOrderHash("1tRabc")
	if !strings.HasPrefix(oh, "OR") || len(oh) < 40 {
		t.Fatal(oh)
	}
	th := GetTransferHash("hello")
	if !strings.HasPrefix(th, "tR") || !IsValid58(th[2:]) {
		t.Fatal(th)
	}
	// Order hash: SHA256("hello") = 2CF24DBA...; hand check by big.Int.
	n, _ := new(big.Int).SetString("2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824", 16)
	if got := GetOrderHash("hello"); got != "OR"+n.Text(36) {
		t.Fatalf("%s vs OR%s", got, n.Text(36))
	}
}

func TestCanonicalSignVerify(t *testing.T) {
	kp := GenerateKeyPair()
	sig := SignCanonical(kp.PrivateKey, "ORDER1", "TRFR", "100", "NA", "NB")
	if sig == "" || !VerifyCanonical(kp.PublicKey, sig, "ORDER1", "TRFR", "100", "NA", "NB") {
		t.Fatal("round trip")
	}
	// FIX(H-07): fields are length-prefixed, so moving a character from one
	// field to the next changes the message.
	if VerifyCanonical(kp.PublicKey, sig, "ORDER1", "TRFR", "10", "0NA", "NB") {
		t.Fatal("field boundary ambiguity")
	}
	// FIX(H-07): domain separation.
	if VerifyCanonical(kp.PublicKey, sig, "CERT1", "TRFR", "100", "NA", "NB") {
		t.Fatal("domain confusion")
	}
	// FIX(H-08): text that differs only in characters the lenient Base64
	// decoder used to drop is now a different message.
	s2 := SignCanonical(kp.PrivateKey, "D", "update 0.4.4")
	if VerifyCanonical(kp.PublicKey, s2, "D", "update 0.44") {
		t.Fatal("lenient decoding is back")
	}
	if VerifyCanonical(GenerateKeyPair().PublicKey, sig, "ORDER1", "TRFR", "100", "NA", "NB") {
		t.Fatal("wrong key")
	}
}

// FIX(M-13): a high-S twin of a valid signature is refused.
func TestLowSEnforced(t *testing.T) {
	kp := GenerateKeyPair()
	for i := 0; i < 20; i++ {
		sig := SignCanonical(kp.PrivateKey, "D", "x", string(rune('a'+i)))
		der := DecodeBase64(sig)
		var sg ecdsaSig
		if _, err := asn1.Unmarshal(der, &sg); err != nil {
			t.Fatal(err)
		}
		if sg.S.Cmp(secpHalfN) > 0 {
			t.Fatal("signer produced high S")
		}
		twin := new(big.Int).Sub(secpN, sg.S)
		d2, _ := asn1.Marshal(ecdsaSig{sg.R, twin})
		if VerifyCanonical(kp.PublicKey, EncodeBase64(d2), "D", "x", string(rune('a'+i))) {
			t.Fatal("high-S twin accepted")
		}
	}
}

func TestCertificateAudienceAndNonce(t *testing.T) {
	kp := GenerateKeyPair()
	c := GetCertificate(kp.PublicKey, kp.PrivateKey, "exchange.example", "n0nce", "1700000000")
	addr, ts := CheckCertificate(c, "exchange.example", "n0nce")
	if addr != GetAddressFromPublicKey(kp.PublicKey, 0) || ts != "1700000000" {
		t.Fatalf("%q %q", addr, ts)
	}
	// FIX(L-05): a certificate cannot be reused for another audience or nonce.
	if a, _ := CheckCertificate(c, "evil.example", "n0nce"); a != "" {
		t.Fatal("audience ignored")
	}
	if a, _ := CheckCertificate(c, "exchange.example", "other"); a != "" {
		t.Fatal("nonce ignored")
	}
}

func TestIDHash(t *testing.T) {
	// first 16 bytes of SHA-256("abc")
	if IDHash("abc") != "BA7816BF8F01CFEA414140DE5DAE2223" {
		t.Fatal(IDHash("abc"))
	}
}

func TestBase64(t *testing.T) {
	for _, s := range []string{"", "f", "fo", "foo", "foob", "fooba", "foobar"} {
		enc := EncodeBase64([]byte(s))
		if string(DecodeBase64(enc)) != s {
			t.Errorf("%q", s)
		}
	}
	if EncodeBase64([]byte("foobar")) != "Zm9vYmFy" || EncodeBase64([]byte("fo")) != "Zm8=" {
		t.Error("vector")
	}
}

func TestGetMultiSourceDuplicateInsertBug(t *testing.T) {
	// Real addresses from the repository golden data (gvts.psk).
	a := "N2vWyg8xm1JK3CDb8VfRxpEAnbmJWEF"
	b := "N486ha3uGaGPFqohMGV1HY7WoBAs5C2"
	if _, ok := GetMultiSource(a+","+b, 2); !ok {
		t.Fatal("two ordered addresses must work")
	}
	// b < a is false, a < b true: inserting b before a path.
	got, ok := GetMultiSource(b+","+a, 2)
	if ok {
		t.Logf("ordered: %s", got)
	}
	if _, ok := GetMultiSource(a+","+a, 2); ok {
		t.Fatal("duplicates must fail")
	}
}

func FuzzParsersNoPanic(f *testing.F) {
	f.Add("N3DthVsfEUtqrgWFHTEB6F88xLkT3Df")
	f.Add("")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, s string) {
		IsValidHashAddress(s)
		B16ToB58(s)
		B16ToB36(s)
		B58ToB16(s)
		B58ToB10(s)
		B10ToB58(s)
		B10ToB16(s)
		DecodeBase64(s)
		CheckCertificate(s, s, s)
		VerifyCanonical(s, s, s, s)
		GetMultiSource(s, 2)
	})
}

// Expected values derived by hand from fcl-base base64.pp (GetSize, Read).
func TestDecodeBase64FPCMime(t *testing.T) {
	for in, want := range map[string]string{
		"QUJD": "ABC", "QUI=": "AB", "QUI": "AB", "QQ==": "A", "QQ": "A", "QUJDQUI*": "ABC",
		"QUJDQU": "ABCA", "": "", "QU==QUJD": "A", "Q": "", "QUJD\nQUJD": "ABCABC", "QU*JD": "ABC",
		"=QUJ": "", "QUJDQUJD=": "ABCABC", "QUJDQUJDQUJ*": "ABCABC",
	} {
		if got := string(DecodeBase64(in)); got != want {
			t.Errorf("DecodeBase64(%q) = %q want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "A", "AB", "ABC", "abc\xff\x00"} {
		if got := DecodeBase64(EncodeBase64([]byte(in))); string(got) != in {
			t.Errorf("round trip %q: %q", in, got)
		}
	}
}

func FuzzDecodeBase64(f *testing.F) {
	for _, s := range []string{"", "QUJD", "QUI=", "QUJDQUI*", "====", "A", strings.Repeat("QUJD", 400) + "=QUJD"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = DecodeBase64(s)
		b := DecodeBase64(EncodeBase64([]byte(s)))
		if string(b) != s {
			t.Fatalf("round trip %q -> %q", s, b)
		}
	})
}
