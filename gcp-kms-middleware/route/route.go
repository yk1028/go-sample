package route

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"

	gcpkms "github.com/yk1028/go-sample/gcp-kms-middleware/gcp-kms"
	"github.com/yk1028/go-sample/gcp-kms-middleware/keyinfo"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	router.GET("/ping", func(ctx *gin.Context) {
		ctx.String(200, "pong")
	})

	router.GET("/publickey/relayer1", func(ctx *gin.Context) {
		name := keyinfo.GetKeyName("relayer1")
		publicKey, err := gcpkms.GetPublicKey(name, ctx)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
		}

		ctx.JSON(http.StatusOK, gin.H{
			"publicKey": publicKey,
		})
	})

	router.GET("/publickey/relayer2", func(ctx *gin.Context) {
		name := keyinfo.GetKeyName("relayer2")
		publicKey, err := gcpkms.GetPublicKey(name, ctx)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
		}

		ctx.JSON(http.StatusOK, gin.H{
			"publicKey": publicKey,
		})
	})

	router.POST("/sign/relayer1", func(ctx *gin.Context) {
		signature, err := sign("relayer1", ctx)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
		}

		ctx.JSON(http.StatusOK, gin.H{
			"signature": signature,
		})
	})

	router.POST("/sign/relayer2", func(ctx *gin.Context) {
		signature, err := sign("relayer2", ctx)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
		}

		ctx.JSON(http.StatusOK, gin.H{
			"signature": signature,
		})
	})

	return router
}

func sign(key string, ctx *gin.Context) (string, error) {
	body := ctx.Request.Body
	value, err := ioutil.ReadAll(body)
	if err != nil {
		fmt.Println(err.Error())
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(value), &data)

	tx := data["tx"].(string)

	return gcpkms.Sign(keyinfo.GetKeyName(key), tx)
}
