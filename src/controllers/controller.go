package controllers

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/labstack/echo"
	"github.com/qiz029/go-kms-gcp/src/cipher"
	"github.com/qiz029/go-kms-gcp/src/keys"
	"github.com/qiz029/go-kms-gcp/src/logic"
)

func Key(c echo.Context) error {
	var key [32]byte
	key = keys.GetKey()
	return c.String(http.StatusCreated, cipher.Base64Encode(key[:]))
}

func Encrypt(c echo.Context) error {
	// key [32]byte := keys.GetKey("12345678901234567890123456789012")
	content := c.Request().Body
	key := keys.GetKey()
	body, err := ioutil.ReadAll(content)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(string(body))
	return c.String(http.StatusOK, logic.ConcateEncrypt(key[:], string(body)))
}

func Decrypt(c echo.Context) error {
	content := c.Request().Body
	body, err := ioutil.ReadAll(content)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(string(body))
	return c.String(http.StatusOK, logic.ConcateDecrypt(string(body)))
}

func EncryptCustom(c echo.Context) error {
	pid := c.Param("pid")
	// pid_int, err := strconv.Atoi(pid)
	// if err != nil {
	// 	panic(err)
	// }
	cid := c.Param("cid")
	cid_int, err1 := strconv.Atoi(cid)
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("Encrypting with Project Id " + pid + " and cid " + cid)
	content := c.Request().Body
	key := keys.GetKey()
	body, err2 := ioutil.ReadAll(content)
	if err2 != nil {
		panic(err2.Error())
	}
	encryptedPayload := logic.ConcateEncrypt_cmk(key[:], string(body), cid_int)
	return c.String(http.StatusOK, encryptedPayload)
}

func DecryptCustom(c echo.Context) error {
	pid := c.Param("pid")
	cid := c.Param("cid")
	cid_int, err1 := strconv.Atoi(cid)
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("Decrypting with Project Id " + pid + " and cid " + cid)
	content := c.Request().Body
	body, err := ioutil.ReadAll(content)
	if err != nil {
		panic(err.Error())
	}
	payload, err2 := logic.ConcateDecrypt_cmk(string(body), cid_int)
	if err2 != nil {
		return c.String(http.StatusNotFound, "The cmk is not found")
	}
	return c.String(http.StatusOK, payload)
}
