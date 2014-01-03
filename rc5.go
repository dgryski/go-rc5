// Package rc5 implements the RC5 cipher
/*

For more information, please see:
    https://en.wikipedia.org/wiki/RC5
    http://www.ietf.org/rfc/rfc2040.txt


*/
package rc5

import (
	"crypto/cipher"
	"strconv"
)

const (
	rounds    = 12
	roundKeys = 2 * (rounds + 1)
)

type rc5cipher struct {
	rk [roundKeys]uint32
}

func rotl32(k uint32, rot uint32) uint32 {
	return (k << rot) | (k >> (32 - rot))
}

func rotr32(k uint32, rot uint32) uint32 {
	return (k >> rot) | (k << (32 - rot))
}

type KeySizeError int

func (k KeySizeError) Error() string { return "rc5: invalid key size " + strconv.Itoa(int(k)) }

// New returns a cipher.Block implementing RC5-32/12/16.  The key argument must be 16 bytes.
func New(key []byte) (cipher.Block, error) {

	if l := len(key); l != 16 {
		return nil, KeySizeError(l)
	}

	c := &rc5cipher{}

	const keyWords = 4

	var L [keyWords]uint32

	for i := 0; i < keyWords; i++ {
		L[i] = getUint32(key)
		key = key[4:]
	}

	copy(c.rk[:], skeytable)

	var A uint32
	var B uint32
	var i, j int

	for k := 0; k < 3*roundKeys; k++ {
		c.rk[i] = rotl32(c.rk[i]+(A+B), 3)
		A = c.rk[i]
		L[j] = rotl32(L[j]+(A+B), (A+B)&31)
		B = L[j]

		i = (i + 1) % roundKeys
		j = (j + 1) % keyWords
	}

	return c, nil
}

func (c *rc5cipher) BlockSize() int { return 8 }

func (c *rc5cipher) Encrypt(dst, src []byte) {

	A := getUint32(src) + c.rk[0]
	B := getUint32(src[4:]) + c.rk[1]

	kidx := 2

	for r := 0; r < rounds; r++ {
		A = rotl32(A^B, B&31) + c.rk[kidx]
		B = rotl32(B^A, A&31) + c.rk[kidx+1]
		kidx += 2
	}

	putUint32(dst, A)
	putUint32(dst[4:], B)
}

func (c *rc5cipher) Decrypt(dst, src []byte) {

	A := getUint32(src)
	B := getUint32(src[4:])

	kidx := 2 * rounds

	for r := 0; r < rounds; r++ {
		B = rotr32(B-c.rk[kidx+1], A&31) ^ A
		A = rotr32(A-c.rk[kidx], B&31) ^ B
		kidx -= 2
	}

	putUint32(dst[4:], B-c.rk[1])
	putUint32(dst, A-c.rk[0])
}

// avoid pulling in encoding/binary

func getUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func putUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// skeytable computed from
/*

Pw = uint32(0xb7e15163)
Qw = uint32(0x9e3779b9)

    T = 2*(R+1);
    S[0] = Pw;
    for (i = 1 ; i < T ; i++)  {
        S[i] = S[i-1] + Qw;
    }
*/

var skeytable = []uint32{
	0xb7e15163, 0x5618cb1c, 0xf45044d5, 0x9287be8e, 0x30bf3847, 0xcef6b200, 0x6d2e2bb9, 0x0b65a572,
	0xa99d1f2b, 0x47d498e4, 0xe60c129d, 0x84438c56, 0x227b060f, 0xc0b27fc8, 0x5ee9f981, 0xfd21733a,
	0x9b58ecf3, 0x399066ac, 0xd7c7e065, 0x75ff5a1e, 0x1436d3d7, 0xb26e4d90, 0x50a5c749, 0xeedd4102,
	0x8d14babb, 0x2b4c3474,
}
