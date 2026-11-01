package crypto

import (
	"bytes"
	"encoding/asn1"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Verification and point decoding use a small affine implementation over
// math/big: they handle public data only. Everything that touches a private
// scalar (signing, key generation) is done by dcrd's secp256k1, whose scalar
// multiplication is constant time.

var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

type point struct{ x, y *big.Int } // nil x means infinity

func (a point) inf() bool { return a.x == nil }

func modInv(a, m *big.Int) *big.Int { return new(big.Int).ModInverse(a, m) }

func pointAdd(a, b point) point {
	if a.inf() {
		return b
	}
	if b.inf() {
		return a
	}
	var lam *big.Int
	if a.x.Cmp(b.x) == 0 {
		if a.y.Cmp(b.y) != 0 || a.y.Sign() == 0 {
			return point{}
		}
		num := new(big.Int).Mul(a.x, a.x)
		num.Mul(num, big.NewInt(3))
		den := new(big.Int).Lsh(a.y, 1)
		lam = num.Mul(num, modInv(den, secpP))
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).Sub(b.x, a.x)
		den.Mod(den, secpP)
		lam = num.Mul(num, modInv(den, secpP))
	}
	lam.Mod(lam, secpP)
	x := new(big.Int).Mul(lam, lam)
	x.Sub(x, a.x)
	x.Sub(x, b.x)
	x.Mod(x, secpP)
	y := new(big.Int).Sub(a.x, x)
	y.Mul(y, lam)
	y.Sub(y, a.y)
	y.Mod(y, secpP)
	return point{x, y}
}

func scalarMult(p point, k *big.Int) point {
	var r point
	q := p
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			r = pointAdd(r, q)
		}
		q = pointAdd(q, q)
	}
	return r
}

func basePoint() point { return point{secpGx, secpGy} }

func onCurve(p point) bool {
	if p.inf() || p.x.Sign() < 0 || p.x.Cmp(secpP) >= 0 || p.y.Sign() < 0 || p.y.Cmp(secpP) >= 0 {
		return false
	}
	l := new(big.Int).Mul(p.y, p.y)
	l.Mod(l, secpP)
	r := new(big.Int).Mul(p.x, p.x)
	r.Mul(r, p.x)
	r.Add(r, big.NewInt(7))
	r.Mod(r, secpP)
	return l.Cmp(r) == 0
}

// decodePoint mirrors ECCurve.DecodePoint (BouncyCastle semantics):
// 02/03 compressed, 04 uncompressed, 06/07 hybrid; the point must be on the
// curve.
func decodePoint(b []byte) (point, bool) {
	if len(b) == 0 {
		return point{}, false
	}
	switch b[0] {
	case 2, 3:
		if len(b) != 33 {
			return point{}, false
		}
		x := new(big.Int).SetBytes(b[1:])
		if x.Cmp(secpP) >= 0 {
			return point{}, false
		}
		r := new(big.Int).Mul(x, x)
		r.Mul(r, x)
		r.Add(r, big.NewInt(7))
		r.Mod(r, secpP)
		y := new(big.Int).ModSqrt(r, secpP)
		if y == nil {
			return point{}, false
		}
		if y.Bit(0) != uint(b[0]&1) {
			y.Sub(secpP, y)
		}
		return point{x, y}, true
	case 4, 6, 7:
		if len(b) != 65 {
			return point{}, false
		}
		p := point{new(big.Int).SetBytes(b[1:33]), new(big.Int).SetBytes(b[33:])}
		if b[0] != 4 && p.y.Bit(0) != uint(b[0]&1) {
			return point{}, false
		}
		return p, onCurve(p)
	}
	return point{}, false
}

func encodePoint(p point) []byte {
	out := make([]byte, 65)
	out[0] = 4
	p.x.FillBytes(out[1:33])
	p.y.FillBytes(out[33:])
	return out
}

type ecdsaSig struct{ R, S *big.Int }

var secpHalfN = new(big.Int).Rsh(secpN, 1)

// ecdsaSignDigest signs a 32 byte digest with private scalar d and returns
// the DER encoding. FIX(M-13): the S value is normalised to the low half of
// the group order, so a signature cannot be re-encoded into a second valid
// one (nosocrypto.pas:217-228 used SHA-1 and accepted either S).
//
// FIX(F-9): signing is done by dcrd's secp256k1 package, which multiplies in
// constant time and derives the nonce by RFC 6979 from the key and the digest.
// The home-made ladder above branched on the bits of a random nonce (its time
// follows the nonce, the classic input of a lattice attack on a signing
// oracle). The bytes are the same kind as before: DER, low S, so the verifier
// below accepts them unchanged. The signature of one message is now the same
// every time.
func ecdsaSignDigest(h []byte, d *big.Int) ([]byte, bool) {
	if d.Sign() <= 0 || d.Cmp(secpN) >= 0 || len(h) != 32 {
		return nil, false
	}
	var raw [32]byte
	d.FillBytes(raw[:])
	var k secp.ModNScalar
	overflow := k.SetByteSlice(raw[:])
	for i := range raw {
		raw[i] = 0
	}
	if overflow || k.IsZero() {
		return nil, false
	}
	priv := secp.NewPrivateKey(&k)
	defer priv.Zero()
	return dcrecdsa.Sign(priv, h).Serialize(), true
}

// ecdsaVerifyDigest verifies a DER signature over a 32 byte digest and
// rejects high-S values (FIX(M-13)).
func ecdsaVerifyDigest(h, der []byte, pub point) bool {
	var sg ecdsaSig
	rest, err := asn1.Unmarshal(der, &sg)
	if err != nil || len(rest) != 0 || sg.R == nil || sg.S == nil {
		return false
	}
	if sg.R.Sign() < 1 || sg.S.Sign() < 1 || sg.R.Cmp(secpN) >= 0 || sg.S.Cmp(secpN) >= 0 {
		return false
	}
	if sg.S.Cmp(secpHalfN) > 0 {
		return false
	}
	// Strict DER: asn1.Unmarshal tolerates extra elements inside the SEQUENCE;
	// the only accepted bytes are the re-marshalled (R, S).
	if canon, err := asn1.Marshal(sg); err != nil || !bytes.Equal(canon, der) {
		return false
	}
	e := new(big.Int).SetBytes(h)
	c := modInv(sg.S, secpN)
	u1 := new(big.Int).Mul(e, c)
	u1.Mod(u1, secpN)
	u2 := new(big.Int).Mul(sg.R, c)
	u2.Mod(u2, secpN)
	pt := pointAdd(scalarMult(basePoint(), u1), scalarMult(pub, u2))
	if pt.inf() {
		return false
	}
	v := new(big.Int).Mod(pt.x, secpN)
	return v.Cmp(sg.R) == 0
}
