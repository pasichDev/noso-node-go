package crypto

import (
	"encoding/binary"
	"math/bits"
)

// RIPEMD-160, implemented locally to keep the module dependency free.
// Reference: Dobbertin, Bosselaers, Preneel (1996).

var (
	rmdR1 = [80]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13}
	rmdR2 = [80]uint8{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11}
	rmdS1 = [80]uint8{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6}
	rmdS2 = [80]uint8{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11}
	rmdK1 = [5]uint32{0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E}
	rmdK2 = [5]uint32{0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000}
)

func rmdF(j int, x, y, z uint32) uint32 {
	switch j / 16 {
	case 0:
		return x ^ y ^ z
	case 1:
		return (x & y) | (^x & z)
	case 2:
		return (x | ^y) ^ z
	case 3:
		return (x & z) | (y & ^z)
	}
	return x ^ (y | ^z)
}

func ripemd160Sum(msg []byte) [20]byte {
	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	padded := append([]byte(nil), msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(msg))*8)
	padded = append(padded, l[:]...)
	for off := 0; off < len(padded); off += 64 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(padded[off+4*i:])
		}
		a1, b1, c1, d1, e1 := h[0], h[1], h[2], h[3], h[4]
		a2, b2, c2, d2, e2 := h[0], h[1], h[2], h[3], h[4]
		for j := 0; j < 80; j++ {
			t := bits.RotateLeft32(a1+rmdF(j, b1, c1, d1)+x[rmdR1[j]]+rmdK1[j/16], int(rmdS1[j])) + e1
			a1, e1, d1, c1, b1 = e1, d1, bits.RotateLeft32(c1, 10), b1, t
			t = bits.RotateLeft32(a2+rmdF(79-j, b2, c2, d2)+x[rmdR2[j]]+rmdK2[j/16], int(rmdS2[j])) + e2
			a2, e2, d2, c2, b2 = e2, d2, bits.RotateLeft32(c2, 10), b2, t
		}
		t := h[1] + c1 + d2
		h[1] = h[2] + d1 + e2
		h[2] = h[3] + e1 + a2
		h[3] = h[4] + a1 + b2
		h[4] = h[0] + b1 + c2
		h[0] = t
	}
	var out [20]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}
