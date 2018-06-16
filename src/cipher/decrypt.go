package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt( key []byte, ciphertext []byte ) string {
	if (len(key) != 32) {
		panic(32)
	}

	nonce := ciphertext[:12]

	block, err := aes.NewCipher([]byte(key[:]))
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}

