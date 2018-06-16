package logic

import (
	"fmt"
	"log"

	"github.com/qiz029/go-kms-gcp/src/cipher"
	"github.com/qiz029/go-kms-gcp/src/crypto"
	"github.com/qiz029/go-kms-gcp/src/keys"
)

var CMK [32]byte = keys.GetKey()
var location = "us-west1"
var project_id = "engaged-domain-203305"
var key_ring = "playground_key_ring"
var key_id_str = "key2"

func Masterkey_creation() {

	// first create keyring
	err := crypto.CreateKeyring(project_id, location, key_ring)
	if err != nil {
		log.Println(err)
	}

	// then create a key
	err = crypto.CreateCryptoKey(project_id, key_ring, location, key_id_str)
	if err != nil {
		log.Println(err)
	}
}

func Masterkey_keyRing_creation() {
	// first create keyring
	err := crypto.CreateKeyring(project_id, location, key_ring)
	if err != nil {
		log.Println(err)
	}
}

func masterkey_creation_with_cmkid(cmk_name string) error {
	// then create a key
	err := crypto.CreateCryptoKey(project_id, key_ring, location, cmk_name)
	if err != nil {
		return err
	}
	return nil
}

func masterkey_encryption(rawtext string) string {
	// then encrypt the raw text
	rawByte, err := cipher.Base64Decode(rawtext)
	if err != nil {
		log.Panicln(err)
	}
	encrypted_text, err1 := crypto.Encrypt(project_id, location, key_ring, key_id_str, rawByte)
	if err1 != nil {
		panic(err1)
	}

	fmt.Println(string(encrypted_text))
	return cipher.Base64Encode(encrypted_text)
}

func masterkey_encryption_with_cmkname(rawtext string, keyName string) string {
	// then encrypt the raw text
	rawByte, err := cipher.Base64Decode(rawtext)
	if err != nil {
		log.Panicln(err)
	}
	encrypted_text, err1 := crypto.Encrypt(project_id, location, key_ring, keyName, rawByte)
	if err1 != nil {
		panic(err1)
	}

	fmt.Println(string(encrypted_text))
	return cipher.Base64Encode(encrypted_text)
}

func mastekey_decryption(encrypted_text string) string {
	// then decrypt the ciphered text
	encrypted_bytes, err := cipher.Base64Decode(encrypted_text)
	if err != nil {
		log.Panicln(err)
	}
	actual_text, err2 := crypto.Decrypt(project_id, location, key_ring, key_id_str, encrypted_bytes)
	if err2 != nil {
		panic(err2)
	}

	fmt.Println("The text we got is " + string(actual_text))
	return cipher.Base64Encode(actual_text)
}

func masterkey_decryption_with_cmkname(encrypted_text string, keyName string) string {
	// then decrypt the ciphered text
	encrypted_bytes, err := cipher.Base64Decode(encrypted_text)
	if err != nil {
		log.Panicln(err)
	}
	actual_text, err2 := crypto.Decrypt(project_id, location, key_ring, keyName, encrypted_bytes)
	if err2 != nil {
		panic(err2)
	}

	fmt.Println("The text we got is " + string(actual_text))
	return cipher.Base64Encode(actual_text)
}
