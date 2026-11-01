package crypto

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
)

// F-9: the signer is deterministic (RFC 6979). The vector is the one in the
// test data of github.com/decred/dcrd/dcrec/secp256k1/v4 (ecdsa/signature_test.go,
// "key 0x1, blake256(0x01020304), rfc6979 nonce").
func TestSignerFollowsRFC6979(t *testing.T) {
	h, _ := hex.DecodeString("c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7")
	r, _ := new(big.Int).SetString("c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09", 16)
	s, _ := new(big.Int).SetString("00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560", 16)
	want, err := asn1.Marshal(ecdsaSig{r, s})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ecdsaSignDigest(h, big.NewInt(1))
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("signature %x, want %x", got, want)
	}
	// and the verifier of this package accepts it
	g := basePoint()
	if !ecdsaVerifyDigest(h, got, g) {
		t.Fatal("the existing verifier refused the signature")
	}
}

// Signatures stay valid for the existing verification, for keys of any
// length, and one message always gives one signature.
func TestSignerOutputVerifiesAndIsStable(t *testing.T) {
	for i := 0; i < 20; i++ {
		kp := GenerateKeyPair()
		sig := SignCanonical(kp.PrivateKey, "ORDER1", "a", "b")
		if sig == "" || !VerifyCanonical(kp.PublicKey, sig, "ORDER1", "a", "b") {
			t.Fatalf("key %d: signature does not verify", i)
		}
		if again := SignCanonical(kp.PrivateKey, "ORDER1", "a", "b"); again != sig {
			t.Fatal("the same message was signed two ways")
		}
		if VerifyCanonical(kp.PublicKey, sig, "ORDER1", "a", "c") {
			t.Fatal("signature valid for another message")
		}
		// the public key is the one the scalar gives in the verifier's own arithmetic
		d := new(big.Int).SetBytes(DecodeBase64Lenient(kp.PrivateKey))
		pt, ok := decodePoint(DecodeBase64Lenient(kp.PublicKey))
		want := scalarMult(basePoint(), d)
		if !ok || pt.x.Cmp(want.x) != 0 || pt.y.Cmp(want.y) != 0 {
			t.Fatal("generated public key does not belong to the private key")
		}
	}
	// a short scalar (a leading zero byte is not stored) and the limits
	short := EncodeBase64(new(big.Int).Lsh(big.NewInt(1), 200).Bytes())
	if SignCanonical(short, "X", "m") == "" {
		t.Fatal("a short private key cannot sign")
	}
	for _, bad := range []*big.Int{big.NewInt(0), new(big.Int).Set(secpN), new(big.Int).Add(secpN, big.NewInt(1))} {
		if _, ok := ecdsaSignDigest(make([]byte, 32), bad); ok {
			t.Fatalf("scalar %x signed", bad)
		}
	}
}
