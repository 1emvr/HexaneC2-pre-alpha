package main

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const numRounds = 64
const BlockSize = 8

type KeySizeError int
type Cipher struct {
	table [64]uint32
}

func (c *Cipher) BlockSize() int          { return BlockSize }
func (c *Cipher) Encrypt(dst, src []byte) { encryptBlock(c, dst, src) }
func (c *Cipher) Decrypt(dst, src []byte) { decryptBlock(c, dst, src) }

func SeCreateKey(length int) []byte {

	rand.Seed(time.Now().UnixNano())
	str := make([]byte, length)

	for i := range str {
		str[i] = characters[rand.Intn(len(characters))]
	}

	return str
}

func GetHashFromString(str string) string {
	var (
		sum32   = uint32(2166136261)
		prime32 = uint32(16777619)
	)

	hash := sum32

	for i := 0; i < len(str); i++ {
		hash ^= uint32(str[i])
		hash *= prime32
	}

	name := strings.TrimRight(str, "\n")

	if name == "KERNEL32.DLL" {
		name = "KERNEL10"
	} else if name == "KERNEL32.dll" {
		name = "KERNEL7"
	} else {
		name = str
	}

	return fmt.Sprintf("#define %s 0x%x", strings.ToUpper(strings.Split(name, ".")[0]), hash)
}

func NewCipher(key []byte) (*Cipher, error) {

	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16:
		break
	}

	c := new(Cipher)
	initCipher(c, key)

	return c, nil
}

func XteaDivide(data []byte) [][]byte {
	var (
		sections    [][]byte
		sectionSize = 8
	)

	for i := 0; i < len(data); i += sectionSize {
		end := i + sectionSize
		sections = append(sections, data[i:end])
	}

	return sections
}

func CryptXtea(config, key []byte, encrypt bool) ([]byte, error) {
	var (
		out    []byte
		err    error
		cipher *Cipher
	)

	if cipher, err = NewCipher(key); err != nil {
		return nil, err
	}

	sections := XteaDivide(config)
	out = make([]byte, 0)

	for _, section := range sections {
		buf := make([]byte, 8)

		if encrypt {
			cipher.Encrypt(buf, section)
		} else {
			cipher.Decrypt(buf, section)
		}

		out = append(out, buf...)
	}

	return out, nil
}

// blockToUint32 reads an 8 byte slice into two uint32s.
// The block is treated as big endian.
func blockToUint32(src []byte) (uint32, uint32) {
	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	return r0, r1
}

// uint32ToBlock writes two uint32s into an 8 byte data block.
// Values are written as big endian.
func uint32ToBlock(v0, v1 uint32, dst []byte) {
	dst[0] = byte(v0 >> 24)
	dst[1] = byte(v0 >> 16)
	dst[2] = byte(v0 >> 8)
	dst[3] = byte(v0)
	dst[4] = byte(v1 >> 24)
	dst[5] = byte(v1 >> 16)
	dst[6] = byte(v1 >> 8)
	dst[7] = byte(v1 >> 0)
}

func encryptBlock(c *Cipher, dst, src []byte) {

	v0, v1 := blockToUint32(src)

	for i := 0; i < numRounds; {
		v0 += ((v1<<4 ^ v1>>5) + v1) ^ c.table[i]
		i++

		v1 += ((v0<<4 ^ v0>>5) + v0) ^ c.table[i]
		i++
	}

	uint32ToBlock(v0, v1, dst)
}

func decryptBlock(c *Cipher, dst, src []byte) {

	v0, v1 := blockToUint32(src)

	for i := numRounds; i > 0; {
		i--
		v1 -= ((v0<<4 ^ v0>>5) + v0) ^ c.table[i]

		i--
		v0 -= ((v1<<4 ^ v1>>5) + v1) ^ c.table[i]
	}

	uint32ToBlock(v0, v1, dst)
}

func (k KeySizeError) Error() string {
	return "crypto/xtea: invalid key size " + strconv.Itoa(int(k))
}

func initCipher(c *Cipher, key []byte) {
	// Load the key into four uint32s
	var k [4]uint32
	for i := 0; i < len(k); i++ {
		j := i << 2 // Multiply by 4
		k[i] = uint32(key[j+0])<<24 | uint32(key[j+1])<<16 | uint32(key[j+2])<<8 | uint32(key[j+3])
	}

	// Precalculate the table
	const delta = 0x9E3779B9
	var sum uint32

	// Two rounds of XTEA applied per loop
	for i := 0; i < numRounds; {
		c.table[i] = sum + k[sum&3]
		i++
		sum += delta
		c.table[i] = sum + k[(sum>>11)&3]
		i++
	}
}
