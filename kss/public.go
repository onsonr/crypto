package kss

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/signatures/ecdsa"
	"golang.org/x/crypto/sha3"
)

type PublicKey struct {
	KeyType string
	Key     []byte
}

// Bytes returns the byte representation of the public key
func (k *PublicKey) Bytes() []byte {
	return k.Key
}

// String returns the hex string representation of the public key
func (k *PublicKey) String() string {
	return hex.EncodeToString(k.Key)
}

// VerifySignature verifies the signature of a message
func (k *PublicKey) VerifySignature(msg []byte, sig []byte) bool {
	pp, err := BuildEcPoint(k.Key)
	if err != nil {
		return false
	}
	sigEd, err := ecdsa.DeserializeSecp256k1Signature(sig)
	if err != nil {
		return false
	}
	hash := sha3.New256()
	_, err = hash.Write(msg)
	if err != nil {
		return false
	}
	digest := hash.Sum(nil)
	return curves.VerifyEcdsa(pp, digest[:], sigEd)
}

// Type returns the public key type
func (k *PublicKey) Type() string {
	return k.KeyType
}

// BuildEcPoint builds an elliptic curve point from a compressed byte slice
func BuildEcPoint(pubKey []byte) (*curves.EcPoint, error) {
	crv := curves.K256()
	x := new(big.Int).SetBytes(pubKey[1:33])
	y := new(big.Int).SetBytes(pubKey[33:])
	ecCurve, err := crv.ToEllipticCurve()
	if err != nil {
		return nil, fmt.Errorf("error converting curve: %v", err)
	}
	return &curves.EcPoint{X: x, Y: y, Curve: ecCurve}, nil
}
