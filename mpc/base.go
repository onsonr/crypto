package mpc

import (
	genericecdsa "crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

// RunProtocol runs the protocol between two parties.
func RunProtocol(firstParty protocol.Iterator, secondParty protocol.Iterator) (error, error) {
	var (
		message *protocol.Message
		aErr    error
		bErr    error
	)

	for aErr != protocol.ErrProtocolFinished || bErr != protocol.ErrProtocolFinished {
		// Crank each protocol forward one iteration
		message, bErr = firstParty.Next(message)
		if bErr != nil && bErr != protocol.ErrProtocolFinished {
			return nil, bErr
		}

		message, aErr = secondParty.Next(message)
		if aErr != nil && aErr != protocol.ErrProtocolFinished {
			return aErr, nil
		}
	}
	return aErr, bErr
}

// ComputeEcPoint builds an elliptic curve point from a compressed byte slice
func ComputeEcPoint(pubKey []byte) (*curves.EcPoint, error) {
	crv := curves.K256()
	x := new(big.Int).SetBytes(pubKey[1:33])
	y := new(big.Int).SetBytes(pubKey[33:])
	ecCurve, err := crv.ToEllipticCurve()
	if err != nil {
		return nil, fmt.Errorf("error converting curve: %v", err)
	}
	return &curves.EcPoint{X: x, Y: y, Curve: ecCurve}, nil
}

func ComputeEcdsaPublicKey(pubKey []byte) (*genericecdsa.PublicKey, error) {
	pk, err := ComputeEcPoint(pubKey)
	if err != nil {
		return nil, err
	}
	return &genericecdsa.PublicKey{
		Curve: pk.Curve,
		X:     pk.X,
		Y:     pk.Y,
	}, nil
}

// GetRawPublicKey is the public key for the keyshare
func GetRawPublicKey(ks Share) ([]byte, error) {
	msg, err := ks.Message()
	if err != nil {
		return nil, err
	}
	if ks.Role().IsBob() {
		bobOut, err := dklsv1.DecodeBobDkgResult(msg)
		if err != nil {
			return nil, err
		}
		return bobOut.PublicKey.ToAffineUncompressed(), nil
	} else if ks.Role().IsAlice() {
		aliceOut, err := dklsv1.DecodeAliceDkgResult(msg)
		if err != nil {
			return nil, err
		}
		return aliceOut.PublicKey.ToAffineUncompressed(), nil
	}
	return nil, ErrInvalidKeyshareRole
}

// VerifySignature verifies the signature of a message
func VerifySignature(ks Share, msg []byte, sig []byte) (bool, error) {
	pk, err := ks.PublicKey()
	if err != nil {
		return false, err
	}
	pp, err := ComputeEcPoint(pk)
	if err != nil {
		return false, err
	}
	sigEd, err := DeserializeSignature(sig)
	if err != nil {
		return false, err
	}
	hash := sha3.New256()
	_, err = hash.Write(msg)
	if err != nil {
		return false, err
	}
	digest := hash.Sum(nil)
	return curves.VerifyEcdsa(pp, digest[:], sigEd), nil
}
