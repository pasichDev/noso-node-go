package crypto

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Independent ECDSA vector: key generated and digest signed by OpenSSL 4
// (`openssl pkeyutl -sign` on the raw 32 byte digest, secp256k1); the S value
// of the DER is in the low half of the order. Nothing here comes from this
// package's signer.
const (
	vecPub    = "045e4893f0f171de82175d39d7174e0b6c2b5dcd83518592429e0bbc611148345d616fed777d7a7671c46cf8f830c6210edf9ed8d9b8b5153e2cdd69bf601ad80c"
	vecDigest = "715df4a8985403ba42167015134a823271dcca5d5c353c25ebe182e59eb6820e" // SHA-256("noso independent vector")
	vecSigDER = "3044022060fea0cd1f40e9fe6a2d1a4cb77046cf39f9d1f89792f257307bca692660a3cd022076fbe7749ad2a4a922b362c04d035886da637dfb2cf177ae298fa762c2604f30"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestECDSAIndependentVector(t *testing.T) {
	pt, ok := decodePoint(mustHex(t, vecPub))
	if !ok {
		t.Fatal("vector public key rejected")
	}
	h, der := mustHex(t, vecDigest), mustHex(t, vecSigDER)
	if !ecdsaVerifyDigest(h, der, pt) {
		t.Fatal("independent vector does not verify")
	}
	bad := append([]byte{}, h...)
	bad[0] ^= 1
	if ecdsaVerifyDigest(bad, der, pt) {
		t.Fatal("verifies a different digest")
	}
	// high-S twin of the same signature is a valid ECDSA signature but not canonical
	var sg ecdsaSig
	if _, err := asn1.Unmarshal(der, &sg); err != nil {
		t.Fatal(err)
	}
	twin, _ := asn1.Marshal(ecdsaSig{sg.R, new(big.Int).Sub(secpN, sg.S)})
	if ecdsaVerifyDigest(h, twin, pt) {
		t.Fatal("high-S twin accepted")
	}
}

func TestDERStrict(t *testing.T) {
	pt, _ := decodePoint(mustHex(t, vecPub))
	h, der := mustHex(t, vecDigest), mustHex(t, vecSigDER)
	cases := map[string][]byte{}
	// extra element inside the SEQUENCE (the review's PoC)
	in := append(append([]byte{}, der...), 0x05, 0x00)
	in[1] += 2
	cases["inner NULL"] = in
	cases["trailing byte"] = append(append([]byte{}, der...), 0)
	// long-form (non-minimal) length of the SEQUENCE
	cases["long-form length"] = append([]byte{0x30, 0x81, der[1]}, der[2:]...)
	// zero padded INTEGER r
	z := append([]byte{0x30, der[1] + 1, 0x02, der[3] + 1, 0x00}, der[4:]...)
	cases["padded integer"] = z
	cases["empty"] = nil
	for name, c := range cases {
		if ecdsaVerifyDigest(h, c, pt) {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStrictBase64(t *testing.T) {
	good := map[string]string{"": "", "Zg==": "f", "Zm8=": "fo", "Zm9v": "foo", "Zm9vYg==": "foob"}
	for in, want := range good {
		b, ok := DecodeBase64Strict(in)
		if !ok || string(b) != want {
			t.Errorf("%q -> %q ok=%v", in, b, ok)
		}
	}
	for _, in := range []string{
		"Zm9v*", "Zm9v\n", "Zm9v\r\n", " Zm9v", "Zm9v ", "Zm9", "Zg=", "Zg", // junk, whitespace, missing padding
		"Zh==", "Zm9=", // non-zero trailing bits: a second text for the same bytes
		"Zm9v=AAA", "Zg==Zg==", "=AAA", "Zm9v!!!!", "Zm9v-_-_", // padding mid-string, URL alphabet
		"Zm9v\x00",
	} {
		if b, ok := DecodeBase64Strict(in); ok {
			t.Errorf("%q accepted as %x", in, b)
		}
	}
}

func TestVerifyCanonicalRejectsTextVariants(t *testing.T) {
	kp := GenerateKeyPair()
	sig := SignCanonical(kp.PrivateKey, "D", "x")
	if !VerifyCanonical(kp.PublicKey, sig, "D", "x") {
		t.Fatal("base")
	}
	for _, v := range []string{sig + "*", sig + "!!!!", "\n" + sig, sig + "\n", sig + "=AAAA", " " + sig, strings.Replace(sig, "M", "M.", 1)} {
		if v != sig && VerifyCanonical(kp.PublicKey, v, "D", "x") {
			t.Errorf("signature text variant %q verifies", v[len(v)-6:])
		}
	}
	for _, v := range []string{kp.PublicKey + "*", "\n" + kp.PublicKey, kp.PublicKey + "=AAAA"} {
		if VerifyCanonical(v, sig, "D", "x") {
			t.Errorf("public key text variant %q verifies", v[len(v)-6:])
		}
	}
	der, _ := DecodeBase64Strict(sig)
	inner := append(append([]byte{}, der...), 0x05, 0x00)
	inner[1] += 2
	if VerifyCanonical(kp.PublicKey, EncodeBase64(inner), "D", "x") {
		t.Error("DER with an extra element verifies")
	}
}
