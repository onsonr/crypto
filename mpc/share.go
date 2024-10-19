package mpc

import (
	"strings"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

type Share string

func (k Share) GetSignFunc(msg []byte) (SignFunc, error) {
	curve := curves.K256()
	msgShare, err := k.Message()
	if err != nil {
		return nil, err
	}
	if k.Role().IsBob() {
		return dklsv1.NewBobSign(curve, sha3.New256(), msg, msgShare, protocol.Version1)
	} else if k.Role().IsAlice() {
		return dklsv1.NewAliceSign(curve, sha3.New256(), msg, msgShare, protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

func (k Share) GetRefreshFunc() (RefreshFunc, error) {
	curve := curves.K256()
	msgShare, err := k.Message()
	if err != nil {
		return nil, err
	}
	if k.Role().IsBob() {
		return dklsv1.NewBobRefresh(curve, msgShare, protocol.Version1)
	} else if k.Role().IsAlice() {
		return dklsv1.NewAliceRefresh(curve, msgShare, protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

func (k Share) Message() (*protocol.Message, error) {
	ptrs := strings.Split(string(k), ":")
	return protocol.DecodeMessage(ptrs[1])
}

func (k Share) Role() Role {
	ptrs := strings.Split(string(k), ":")
	return Role(ptrs[0])
}

func (k Share) PublicKey() ([]byte, error) {
	ptrs := strings.Split(string(k), ":")
	msg, err := protocol.DecodeMessage(ptrs[1])
	if err != nil {
		return nil, err
	}
	if k.Role().IsAlice() {
		out, err := dklsv1.DecodeAliceDkgResult(msg)
		if err != nil {
			return nil, err
		}
		return out.PublicKey.ToAffineUncompressed(), nil
	} else if k.Role().IsBob() {
		out, err := dklsv1.DecodeBobDkgResult(msg)
		if err != nil {
			return nil, err
		}
		return out.PublicKey.ToAffineUncompressed(), nil

	}
	return nil, ErrInvalidKeyshareRole
}
