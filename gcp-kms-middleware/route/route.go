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

const (
	appName        = "signing-middleware"
	backend        = "file"
	keyringFileDir = "./"
	hsmKeyInfoDir  = "./keyinfo.json"
)

func SetupRouter() *gin.Engine {

	router := gin.Default()

	keys := initKeys()

	for key, signer := range keys {
		routingKey := key
		routingSigner := signer

		router.GET("/publickey/"+routingKey, func(ctx *gin.Context) {
			getPublicKey(&routingSigner, ctx)
		})

		router.POST("/sign/"+routingKey, func(ctx *gin.Context) {
			sign(&routingSigner, ctx)
		})
	}

	fileKeys := initFileKeys()

	for key, signer := range fileKeys {
		routingKey := key
		routingSigner := signer

		router.GET("/file/publickey/"+routingKey, func(ctx *gin.Context) {
			getPublicKey(&routingSigner, ctx)
		})

		router.POST("/file/sign/"+routingKey, func(ctx *gin.Context) {
			sign(&routingSigner, ctx)
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
		keys[key] = &signer.GcpKmsSigner{Name: name.(string)}
	}

	return keys
}

func getKeyList(keyType string) map[string]interface{} {
	jsonFile, err := os.Open(hsmKeyInfoDir)
	if err != nil {
		fmt.Println(err.Error())
	}

	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	keyinfo := make(map[string]interface{})

	err = json.Unmarshal(byteValue, &keyinfo)
	if err != nil {
		fmt.Println(err.Error())
	}

	return keyinfo[keyType].(map[string]interface{})
}

func initFileKeys() map[string]signer.Signer {
	userInput := strings.NewReader("")

	newKeyring, err := keyring.New(appName, backend, keyringFileDir, userInput, etherhd.EthSecp256k1Option())
	if err != nil {
		fmt.Println(err.Error())
	}

	list, err := newKeyring.List()
	if err != nil {
		fmt.Println(err.Error())
	}

	keys := map[string]signer.Signer{}

	for _, keyInfo := range list {
		keyName := keyInfo.GetName()
		privKey := getFilePrivKey(newKeyring, keyName)
		keys[keyName] = &signer.FileSigner{PrivKey: privKey}
	}

	return keys
}

func getFilePrivKey(fileKeyRing keyring.Keyring, keyName string) sdk.PrivKey {
	armored, err := fileKeyRing.ExportPrivKeyArmor(keyName, "password")
	if err != nil {
		fmt.Println(err.Error())
	}

	decrypted, _, err := crypto.UnarmorDecryptPrivKey(armored, "password")
	if err != nil {
		fmt.Println(err.Error())
	}

	return decrypted
}

func getPublicKey(keySigner *signer.Signer, ctx *gin.Context) {

	publicKey, err := (*keySigner).GetPublicKey()
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	fmt.Println("publickey :", publicKey)

	ctx.JSON(http.StatusOK, gin.H{
		"publicKey": publicKey,
	})
}

func sign(keySigner *signer.Signer, ctx *gin.Context) {

	tx, err := parseTx(ctx.Request.Body)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	signature, err := (*keySigner).Sign(tx)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())
	}

	fmt.Println("signature :", signature)

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
	})
}

func parseTx(body io.ReadCloser) (string, error) {
	value, err := ioutil.ReadAll(body)

	fmt.Println("body", string(value))

	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	json.Unmarshal([]byte(value), &data)

	return data["tx"].(string), nil
}
