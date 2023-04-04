package signer

type Signer interface {
	GetPublicKey() (string, error)
	Sign(base64ToSign string) (string, error)
}
