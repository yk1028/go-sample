package gcpkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"google.golang.org/api/option"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func GetPublicKey(c *gin.Context) (string, error) {

	name := generateName(c)

	// Create the client using gcp service account key file.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile("./service-account.json"))
	if err != nil {
		return "", fmt.Errorf("failed to create kms client: %v", err)
	}
	defer client.Close()

	// Build the request.
	req := &kmspb.GetPublicKeyRequest{
		Name: name,
	}

	// Call the API.
	result, err := client.GetPublicKey(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %v", err)
	}

	key := []byte(result.Pem)

	err = checkCrc32(key, result.PemCrc32C.Value)
	if err != nil {
		return "", err
	}

	publicKey := parsePublickey(key)

	return publicKey, nil
}

func generateName(c *gin.Context) string {
	names := []string{
		"projects",
		c.Param("projects"),
		"locations",
		c.Param("locations"),
		"keyRings",
		c.Param("keyRings"),
		"cryptoKeys",
		c.Param("cryptoKeys"),
		"cryptoKeyVersions",
		c.Param("cryptoKeyVersions")}
	return strings.Join(names, "/")
}

// Optional, but recommended: perform integrity verification on result.
// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
// https://cloud.google.com/kms/docs/data-integrity-guidelines
func checkCrc32(data []byte, pemCrc32CValue int64) error {
	t := crc32.MakeTable(crc32.Castagnoli)
	checkSum := crc32.Checksum(data, t)

	if int64(checkSum) != pemCrc32CValue {
		return fmt.Errorf("getPublicKey: response corrupted in-transit")
	}
	return nil
}

func parsePublickey(key []byte) string {

	block, _ := pem.Decode(key)

	var pki publicKeyInfo

	asn1.Unmarshal(block.Bytes, &pki)
	asn1Data := pki.PublicKey.RightAlign()
	_, x, y := asn1Data[0], asn1Data[1:33], asn1Data[33:]

	x_big := new(big.Int)
	x_big.SetBytes(x)
	y_big := new(big.Int)
	y_big.SetBytes(y)

	pubkey := ecdsa.PublicKey{Curve: crypto.S256(), X: x_big, Y: y_big}

	compPubKey := crypto.CompressPubkey(&pubkey)

	return base64.StdEncoding.EncodeToString(compPubKey)
}
