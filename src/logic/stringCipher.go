package logic

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/qiz029/go-kms-gcp/src/cipher"
	"github.com/qiz029/go-kms-gcp/src/keys"
	"github.com/qiz029/go-kms-gcp/src/model"
)

func ConcateEncrypt_cmk(key []byte, rawData string, cmk_id int, pid int) string {
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

	encrypted_kek := model.GetKek(cmk_id, pid)
	var rawKek []byte
	if encrypted_kek == "" {
		temp := keys.GetKey()
		rawKek = temp[:]
		encryptedKek := masterkey_encryption_with_cmkname(cipher.Base64Encode(rawKek), keyName)
		model.StoreKek(pid, encryptedKek, cmk_id)
	} else {
		var err error
		rawKek, err = cipher.Base64Decode(masterkey_decryption_with_cmkname(encrypted_kek, keyName))
		if err != nil {
			panic(err)
		}
	}

	encryptedData := cipher.Encrypt(key, rawData)
	// encryptedKey := cipher.Encrypt(CMK[:], cipher.Base64Encode(key[:]))
	encryptedKey := cipher.Base64Encode(cipher.Encrypt(rawKek[:], cipher.Base64Encode(key[:])))
	concatedData := encryptedKey + ":" + cipher.Base64Encode(encryptedData[:])
	return concatedData
}

func ConcateDecrypt_cmk(data string, cmk_id int, pid int) (string, error) {
	// need to check if cmk exist already
	cmkName := model.GetCmk(cmk_id)
	var keyName string
	if cmkName == "" {
		return "", errors.New("No cmk record found")
	} else {
		keyName = cmkName
	}

	encrypted_kek := model.GetKek(cmk_id, pid)
	var rawKek []byte
	if encrypted_kek == "" {
		return "", errors.New("No kek record found")
	} else {
		var err error
		rawKek, err = cipher.Base64Decode(masterkey_decryption_with_cmkname(encrypted_kek, keyName))
		if err != nil {
			panic(err)
		}
	}

	splitted := strings.Split(data, ":")
	base64Key := splitted[0]
	rawDEK, err1 := cipher.Base64Decode(base64Key)
	if err1 != nil {
		panic(err1)
	}
	base64EncryptedData := splitted[1]
	key, err := cipher.Base64Decode(cipher.Decrypt(rawKek, rawDEK))
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
