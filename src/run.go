package src

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/qiz029/go-kms-gcp/src/controllers"
	"github.com/qiz029/go-kms-gcp/src/logic"
	"github.com/qiz029/go-kms-gcp/src/model"
)

func Run() {

	router := echo.New()

	router.GET("/key", controllers.Key)

	router.POST("/encrypt", controllers.Encrypt)

	router.POST("/decrypt", controllers.Decrypt)

	router.POST("/pid/:pid/cid/:cid/encrypt", controllers.EncryptCustom)

	router.POST("/pid/:pid/cid/:cid/decrypt", controllers.DecryptCustom)

	router.GET("/", welcome)

	model.Start()

	logic.Masterkey_keyRing_creation()

	router.Logger.Fatal(router.Start(":9999"))

}

func welcome(c echo.Context) error {
	return c.String(http.StatusOK, "welcom")
}
