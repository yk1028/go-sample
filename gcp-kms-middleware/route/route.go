package route

import (
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
		getPublicKey("relayer1", ctx)
	})

	router.GET("/publickey/relayer2", func(ctx *gin.Context) {
		getPublicKey("relayer2", ctx)
	})

	router.POST("/sign/relayer1", func(ctx *gin.Context) {
		sign("relayer1", ctx)
	})

	router.POST("/sign/relayer2", func(ctx *gin.Context) {
		sign("relayer2", ctx)
	})

	return router
}

func getPublicKey(key string, ctx *gin.Context) {
	keyName := keyinfo.GetKeyName(key)
	publicKey, err := gcpkms.GetPublicKey(keyName, ctx)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"publicKey": publicKey,
	})
}

func sign(key string, ctx *gin.Context) {
	keyName := keyinfo.GetKeyName(key)
	tx := parseTx(ctx)

	signature, err := gcpkms.Sign(keyName, tx)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
	})
}
