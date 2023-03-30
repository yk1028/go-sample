package gcpkms

import (
	"context"
	"encoding/asn1"
	"encoding/base64"
	"math/big"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/api/option"
)

type ecdsaStruct struct {
	R, S *big.Int
}

func Sign(name string, base64ToSign string) (string, error) {

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
		Name: name,
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
