package signer

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

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/api/option"
)

type GcpKmsSigner struct {
	Name string
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func (g GcpKmsSigner) GetPublicKey() (string, error) {
	// Create the client using gcp service account key file.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile("./service-account.json"))
	if err != nil {
		return "", fmt.Errorf("failed to create kms client: %v", err)
	}
	defer client.Close()

	// Build the request.
	req := &kmspb.GetPublicKeyRequest{
		Name: g.Name,
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

type ecdsaStruct struct {
	R, S *big.Int
}

func (g GcpKmsSigner) Sign(base64ToSign string) (string, error) {

	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsFile("./service-account.json"))

	if err != nil {
		return "", err
	}
	defer kmsClient.Close()

	bytesToSign, err := base64.StdEncoding.DecodeString(base64ToSign)

	if err != nil {
		return "", err
	}

	digest := crypto.Keccak256(bytesToSign)

	req := &kmspb.AsymmetricSignRequest{
		Name: g.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	}

	signResp, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return "", err
	}

	dec := new(ecdsaStruct)
	asn1.Unmarshal(signResp.Signature, dec)

	secp256k1N, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN := new(big.Int).Div(secp256k1N, new(big.Int).SetInt64(2))

	var r, s *big.Int

	r = dec.R
	if dec.S.Cmp(secp256k1halfN) == 1 {
		s = new(big.Int).Sub(secp256k1N, dec.S)
	} else {
		s = dec.S
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sigBytes := append(rBytes, sBytes...)

	encoded := base64.StdEncoding.EncodeToString(sigBytes)

	return encoded, nil
}
