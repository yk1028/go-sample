package route

import (
	"net/http"

	"github.com/gin-gonic/gin"

	gcpkms "github.com/yk1028/go-sample/go-gin/gcp-kms"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()

	router.GET("/ping", func(ctx *gin.Context) {
		ctx.String(200, "pong")
	})

	router.GET("/publicKey/:projects/:locations/:keyRings/:cryptoKeys/:cryptoKeyVersions", func(ctx *gin.Context) {
		publicKey, err := gcpkms.GetPublicKey(ctx)
		if err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
		}

		ctx.String(200, string(publicKey))
	})
	return router
}
