package route

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/yk1028/go-sample/gcp-kms-middleware/signer"

	"github.com/cosmos/cosmos-sdk/crypto"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/crypto/types"

	etherhd "github.com/evmos/ethermint/crypto/hd"
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

	fileKeys := initFileKeys()

	for key, signer := range fileKeys {
		router.GET("/file/publickey/"+key, func(ctx *gin.Context) {
			getPublicKey(signer, ctx)
		})

		router.POST("/file/sign/"+key, func(ctx *gin.Context) {
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

func initFileKeys() map[string]signer.Signer {
	appName := "signing-middleware"
	backend := "file" // backend file
	dir := "./eth/"
	userInput := strings.NewReader("")

	newKeyring, err := keyring.New(appName, backend, dir, userInput, etherhd.EthSecp256k1Option())
	if err != nil {
		fmt.Println("keyring load error")
		fmt.Print(err)
	}

	list, err := newKeyring.List()
	if err != nil {
		fmt.Println("keyring list error")
		fmt.Print(err)
	}

	keys := map[string]signer.Signer{}

	for _, keyInfo := range list {
		keyName := keyInfo.GetName()
		privKey := getFilePrivKey(newKeyring, keyName)
		fileSigner := signer.FileSigner{PrivKey: privKey}
		keys[keyName] = fileSigner
	}

	return keys
}

func getFilePrivKey(fileKeyRing keyring.Keyring, keyName string) sdk.PrivKey {
	armored, err := fileKeyRing.ExportPrivKeyArmor(keyName, "password1")
	if err != nil {
		fmt.Print(err)
		fmt.Println("export priv key error")
	}

	decrypted, _, err := crypto.UnarmorDecryptPrivKey(armored, "password1")
	if err != nil {
		fmt.Print(err)
		fmt.Println("export priv key unarmor error")
	}

	return decrypted
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
