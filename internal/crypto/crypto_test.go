package crypto

import (
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
	if MD5String("abc") != "900150983CD24FB0D6963F7D28E17F72" {
		t.Error("md5")
	}
	if MD5String("") != MD5OfEmpty {
		t.Error("md5 empty")
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
	b, _ := hexToBytes(hexs)
	want := encodeDigits(new(big.Int).SetBytes(b), B58Alphabet)
	if got := B16ToB58(hexs); got != want {
		t.Fatalf("%s vs %s", got, want)
	}
	if B16ToB58("") != "1" || B16ToB58("zz") != "1" {
		t.Error("defaults")
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

func TestSignVerifyRoundTrip(t *testing.T) {
	kp := GenerateKeyPair()
	addr := GetAddressFromPublicKey(kp.PublicKey, 0)
	if !IsValidHashAddress(addr) {
		t.Fatal("generated address invalid", addr)
	}
	msg := "Customize this " + addr + " myalias"
	sig := GetStringSigned(msg, kp.PrivateKey)
	if sig == "" || !VerifySignedString(msg, sig, kp.PublicKey) {
		t.Fatal("round trip failed")
	}
	// The message is Base64-decoded leniently, so differences in
	// non-alphabet characters do not change the signed bytes.
	if !VerifySignedString("Customize  this"+addr+"myalias", sig, kp.PublicKey) {
		t.Fatal("lenient decode must ignore blanks")
	}
	if VerifySignedString(msg+"X", sig, kp.PublicKey) {
		t.Fatal("tampered message accepted")
	}
	other := GenerateKeyPair()
	if VerifySignedString(msg, sig, other.PublicKey) {
		t.Fatal("wrong key accepted")
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	kp := GenerateKeyPair()
	c := GetCertificate(kp.PublicKey, kp.PrivateKey, "1700000000")
	if c == "" {
		t.Fatal("empty certificate")
	}
	addr, ts := CheckCertificate(c)
	if addr != GetAddressFromPublicKey(kp.PublicKey, 0) || ts != "1700000000" {
		t.Fatalf("%q %q", addr, ts)
	}
}

func TestXor(t *testing.T) {
	e := XorEncode("key", "hello")
	if XorDecode("key", e) != "hello" {
		t.Fatal(e)
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
		XorDecode("k", s)
		CheckCertificate(s)
		VerifySignedString(s, s, s)
		GetMultiSource(s, 2)
	})
}
