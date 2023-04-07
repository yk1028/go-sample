package signer

import (
	"encoding/base64"

	"github.com/cosmos/cosmos-sdk/codec"

	sdk "github.com/cosmos/cosmos-sdk/crypto/types"

	cryptocodec "github.com/evmos/ethermint/crypto/codec"
)

type FileSigner struct {
	PrivKey sdk.PrivKey
}

func init() {
	amino := codec.NewLegacyAmino()
	cryptocodec.RegisterCrypto(amino)
}

func (fs FileSigner) GetPublicKey() (string, error) {
	pubkey := fs.PrivKey.PubKey().Bytes()

	encoded := base64.StdEncoding.EncodeToString(pubkey)

	return encoded, nil
}

func (fs FileSigner) Sign(base64ToSign string) (string, error) {

	body, err := base64.StdEncoding.DecodeString(base64ToSign)
	if err != nil {
		return "", err
	}

	sigBytes, err := fs.PrivKey.Sign(body)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(sigBytes)

	return encoded, nil
}
