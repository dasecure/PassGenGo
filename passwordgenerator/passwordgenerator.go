package passwordgenerator

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
)

const DerivePasswordPath uint32 = 0x40887451

func GeneratePassword(seed, account string, options PasswordOptions) (string, error) {
	data := seed + account
	hash := sha256.Sum256([]byte(data))

	derive := make([]uint32, 9)
	derive[0] = DerivePasswordPath
	for i := 0; i < 8; i++ {
		derive[i+1] = 0x80000000 | (binary.BigEndian.Uint32(hash[i*4:(i+1)*4]) & 0x7fffffff)
	}

	deriveBytes := make([]byte, len(derive)*4)
	for i, v := range derive {
		binary.BigEndian.PutUint32(deriveBytes[i*4:(i+1)*4], v)
	}

	h := hmac.New(sha512.New, []byte(seed+account))
	h.Write(deriveBytes)
	entropy := h.Sum(nil)

	charset := ""
	if options.UseUppercase {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if options.UseLowercase {
		charset += "abcdefghijklmnopqrstuvwxyz"
	}
	if options.UseNumbers {
		charset += "0123456789"
	}
	if options.UseSpecialChars {
		charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	if charset == "" {
		return "", errors.New("at least one character set must be selected")
	}

	password := make([]byte, options.Length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < options.Length; i++ {
		index, _ := new(big.Int).SetBytes(entropy[i*2:i*2+2]).Mod(new(big.Int).SetBytes(entropy[i*2:i*2+2]), charsetLength).Int64()
		password[i] = charset[index]
	}

	return string(password), nil
}

type PasswordOptions struct {
	Length          int
	UseUppercase    bool
	UseLowercase    bool
	UseNumbers      bool
	UseSpecialChars bool
}
