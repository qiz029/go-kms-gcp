package logic

import (
	"fmt"
	"log"
	"strings"

	"github.com/qiz029/go-kms-gcp/src/cipher"
)

func ConcateEncrypt(key []byte, rawData string) string {
	encryptedData := cipher.Encrypt(key, rawData)
	// encryptedKey := cipher.Encrypt(CMK[:], cipher.Base64Encode(key[:]))
	encryptedKey := masterkey_encryption(cipher.Base64Encode(key[:]))
	concatedData := encryptedKey + ":" + cipher.Base64Encode(encryptedData[:])
	return concatedData
}

func ConcateDecrypt(data string) string {
	splitted := strings.Split(data, ":")
	base64Key := splitted[0]
	base64EncryptedData := splitted[1]
	key, err := cipher.Base64Decode(mastekey_decryption(base64Key))
	if err != nil {
		log.Println(err)
	}
	fmt.Println("The key length we got is: ", len(key))
	encryptedData, err := cipher.Base64Decode(base64EncryptedData)
	if err != nil {
		return ""
	}
	return cipher.Decrypt(key, encryptedData)
}
