package route

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/yk1028/go-sample/gcp-kms-middleware/signer"
)

func SetupRouter() *gin.Engine {

	router := gin.Default()

	keys := initKeys()

	for key, signer := range keys {
		router.GET("/publickey/"+key, func(ctx *gin.Context) {
			getPublicKey(signer, ctx)
		})

		router.POST("/sign/"+key, func(ctx *gin.Context) {
			sign(signer, ctx)
		})
	}

	router.GET("/ping", func(ctx *gin.Context) {
		ctx.String(200, "pong")
	})

	return router
}

func initKeys() map[string]signer.Signer {
	keys := map[string]signer.Signer{}

	keyList := getKeyList("gcpkms")

	for key, name := range keyList {
		fmt.Println(key, name)
		keys[key] = signer.GcpKmsSigner{Name: name.(string)}
	}

	return keys
}

func getKeyList(keyType string) map[string]interface{} {
	jsonFile, err := os.Open("./keyinfo.json")
	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	keyinfo := make(map[string]interface{})

	err = json.Unmarshal(byteValue, &keyinfo)
	if err != nil {
		fmt.Println(err)
	}

	return keyinfo[keyType].(map[string]interface{})
}

func getPublicKey(keySigner signer.Signer, ctx *gin.Context) {

	publicKey, err := keySigner.GetPublicKey()
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"publicKey": publicKey,
	})
}

func sign(keySigner signer.Signer, ctx *gin.Context) {

	tx := parseTx(ctx.Request.Body)

	signature, err := keySigner.Sign(tx)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
	})
}

func parseTx(body io.ReadCloser) string {
	value, err := ioutil.ReadAll(body)
	if err != nil {
		fmt.Println(err.Error())
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(value), &data)

	return data["tx"].(string)
}
