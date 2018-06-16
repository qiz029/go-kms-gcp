package logic

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/qiz029/go-kms-gcp/src/cipher"
	"github.com/qiz029/go-kms-gcp/src/crypto"
	"github.com/qiz029/go-kms-gcp/src/keys"
	"github.com/qiz029/go-kms-gcp/src/model"
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

func ConcateEncrypt(key []byte, rawData string) string {
	encryptedData := cipher.Encrypt(key, rawData)
	// encryptedKey := cipher.Encrypt(CMK[:], cipher.Base64Encode(key[:]))
	encryptedKey := masterkey_encryption(cipher.Base64Encode(key[:]))
	concatedData := encryptedKey + ":" + cipher.Base64Encode(encryptedData[:])
	return concatedData
}

func ConcateEncrypt_cmk(key []byte, rawData string, cmk_id int) string {
	// need to check if cmk exist already
	cmkName := model.GetCmk(cmk_id)
	var keyName string
	if cmkName == "" {

		cmk_name, err := exec.Command("uuidgen").Output()
		if err != nil {
			log.Fatal(err)
		}
		cmk_name_str := "cmk_" + string(cmk_name[:len(cmk_name)-1]) + "_key"
		// masterkey creation done, store
		err = masterkey_creation_with_cmkid(cmk_name_str)
		if err != nil {
			panic(err)
		}

		status := model.StoreCmk(cmk_id, cmk_name_str, "2020-09-28 01:00:00")
		if status == false {
			panic("postgres storage failure")
		}
		keyName = cmk_name_str
	} else {
		keyName = cmkName
	}

	encryptedData := cipher.Encrypt(key, rawData)
	// encryptedKey := cipher.Encrypt(CMK[:], cipher.Base64Encode(key[:]))
	encryptedKey := masterkey_encryption_with_cmkname(cipher.Base64Encode(key[:]), keyName)
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

func ConcateDecrypt_cmk(data string, cmk_id int) (string, error) {
	// need to check if cmk exist already
	cmkName := model.GetCmk(cmk_id)
	var keyName string
	if cmkName == "" {
		return "", errors.New("No cmk record found")
	} else {
		keyName = cmkName
	}

	splitted := strings.Split(data, ":")
	base64Key := splitted[0]
	base64EncryptedData := splitted[1]
	key, err := cipher.Base64Decode(masterkey_decryption_with_cmkname(base64Key, keyName))
	if err != nil {
		log.Println(err)
	}
	fmt.Println("The key length we got is: ", len(key))
	encryptedData, err := cipher.Base64Decode(base64EncryptedData)
	if err != nil {
		return "", err
	}
	return cipher.Decrypt(key, encryptedData), nil
}
