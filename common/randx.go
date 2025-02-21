package common

import (
	"crypto/rand"
	"math/big"
)

var (
	AlphaNum           = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	Alpha              = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	AlphaLowerNum      = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	AlphaUpperNum      = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	AlphaLower         = []rune("abcdefghijklmnopqrstuvwxyz")
	AlphaUpperVowels   = []rune("AEIOUY")
	AlphaUpperNoVowels = []rune("BCDFGHJKLMNPQRSTVWXZ")
	AlphaUpper         = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Numeric            = []rune("0123456789")
	SecretCharset      = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.~")
)

func GenerateRandRune(l int, charset []rune) (seq []rune, err error) {
	c := big.NewInt(int64(len(charset)))
	seq = make([]rune, l)

	for i := 0; i < l; i++ {
		r, err := rand.Int(rand.Reader, c)
		if err != nil {
			return seq, err
		}

		rn := charset[r.Uint64()]
		seq[i] = rn
	}

	return seq, nil
}

func GenerateRandString(l int, charset []rune) (string, error) {
	seq, err := GenerateRandRune(l, charset)
	if err != nil {
		return "", err
	}

	return string(seq), nil
}
