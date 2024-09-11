package crypto

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/signatures/ecdsa"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

const (
	MPCRoleUnknown MPCRole = iota
	MPCRoleUser
	MPCRoleValidator
)

var ErrInvalidKeyshareRole = errors.New("invalid keyshare role")

// MPCMessage is the protocol.Message that is used for MPC
type MPCMessage = protocol.Message

func GetMPCMessage(k MPCShare) *protocol.Message {
	return &protocol.Message{
		Payloads: k.GetPayloads(),
		Metadata: k.GetMetadata(),
		Protocol: k.GetProtocol(),
		Version:  k.GetVersion(),
	}
}

type MPCRole int

func (r MPCRole) IsUser() bool {
	return r == MPCRoleUser
}

func (r MPCRole) IsValidator() bool {
	return r == MPCRoleValidator
}

type MPCShare interface {
	// Equals(o MPCShare) bool
	GetPayloads() map[string][]byte
	GetMetadata() map[string]string
	GetPublicKey() []byte
	GetProtocol() string
	GetRole() MPCRole
	GetVersion() uint
}

// GetPublicKey is the public key for the keyshare
func GetPublicKey(ks MPCShare) ([]byte, error) {
	if ks.GetRole().IsUser() {
		bobOut, err := dklsv1.DecodeBobDkgResult(GetMPCMessage(ks))
		if err != nil {
			return nil, err
		}
		return bobOut.PublicKey.ToAffineUncompressed(), nil
	} else if ks.GetRole().IsValidator() {
		aliceOut, err := dklsv1.DecodeAliceDkgResult(GetMPCMessage(ks))
		if err != nil {
			return nil, err
		}
		return aliceOut.PublicKey.ToAffineUncompressed(), nil
	}
	return nil, ErrInvalidKeyshareRole
}

// RefreshFunc is the type for the refresh function
type RefreshFunc interface {
	protocol.Iterator
}

// GetRefreshFunc returns the refresh function for the keyshare
func GetRefreshFunc(ks MPCShare) (RefreshFunc, error) {
	curve := curves.K256()
	if ks.GetRole().IsUser() {
		return dklsv1.NewBobRefresh(curve, GetMPCMessage(ks), protocol.Version1)
	} else if ks.GetRole().IsValidator() {
		return dklsv1.NewAliceRefresh(curve, GetMPCMessage(ks), protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

// SignFunc is the type for the sign function
type SignFunc interface {
	protocol.Iterator
}

// GetSignFunc returns the sign function for the keyshare
func GetSignFunc(ks MPCShare, msg []byte) (SignFunc, error) {
	curve := curves.K256()
	if ks.GetRole().IsUser() {
		return dklsv1.NewBobSign(curve, sha3.New256(), msg, GetMPCMessage(ks), protocol.Version1)
	} else if ks.GetRole().IsValidator() {
		return dklsv1.NewAliceSign(curve, sha3.New256(), msg, GetMPCMessage(ks), protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

type MPCShares = []MPCShare

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

// VerifySignature verifies the signature of a message
func VerifySignature(ks MPCShare, msg []byte, sig []byte) bool {
	pp, err := BuildEcPoint(ks.GetPublicKey())
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
