package crypto

import (
	"crypto/ecdsa"
	"encoding/json"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
	"github.com/onsonr/crypto/tecdsa/dklsv1/dkg"
)

type MPCRole int

const (
	MPCRoleUnknown MPCRole = iota
	MPCRoleUser
	MPCRoleValidator
)

func (r MPCRole) IsUser() bool {
	return r == MPCRoleUser
}

func (r MPCRole) IsValidator() bool {
	return r == MPCRoleValidator
}

// MPCMessage is the protocol.Message that is used for MPC
type MPCMessage *protocol.Message

type MPCPublicKey *ecdsa.PublicKey

type MPCSignature *curves.EcdsaSignature

type MPCShare interface {
	Equals(o MPCShare) bool
	GetPayloads() map[string][]byte
	GetMetadata() map[string]string
	GetPublicKey() []byte
	GetProtocol() string
	GetRole() int32
	GetVersion() uint32
	Marshal() (string, error)
	Unmarshal(data string) error
}

func createKeyshareArray(val MPCMessage, user MPCMessage) ([]MPCShare, error) {
	valShare, err := dklsv1.DecodeAliceDkgResult(val)
	if err != nil {
		return nil, err
	}
	userShare, err := dklsv1.DecodeBobDkgResult(user)
	if err != nil {
		return nil, err
	}
	return []MPCShare{createValKeyshare(valShare, val), createUserKeyshare(userShare, user)}, nil
}

// RefreshFunc is the type for the refresh function
type RefreshFunc interface {
	protocol.Iterator
}

// SignFunc is the type for the sign function
type SignFunc interface {
	protocol.Iterator
}

type valKeyshare struct {
	Message   MPCMessage `json:"message"`
	Role      int        `json:"role"` // 1 for validator, 2 for user
	PublicKey []byte     `json:"public-key"`
}

func createValKeyshare(out *dkg.AliceOutput, msg MPCMessage) valKeyshare {
	return valKeyshare{
		Message:   msg,
		Role:      1,
		PublicKey: out.PublicKey.ToAffineUncompressed(),
	}
}

func (v valKeyshare) GetPayloads() map[string][]byte {
	return v.Message.Payloads
}

func (v valKeyshare) GetMetadata() map[string]string {
	return v.Message.Metadata
}

func (v valKeyshare) GetPublicKey() []byte {
	return v.PublicKey
}

func (v valKeyshare) GetProtocol() string {
	return v.Message.Protocol
}

func (v valKeyshare) GetRole() int32 {
	return int32(v.Role)
}

func (v valKeyshare) GetVersion() uint32 {
	return uint32(v.Message.Version)
}

func (v valKeyshare) Equals(o MPCShare) bool {
	return v.GetProtocol() == o.GetProtocol() &&
		v.GetVersion() == o.GetVersion() &&
		v.GetRole() == o.GetRole()
}

func (v valKeyshare) Marshal() (string, error) {
	jsonBytes, err := json.Marshal(v)
	return string(jsonBytes), err
}

func (v valKeyshare) Unmarshal(data string) error {
	return json.Unmarshal([]byte(data), &v)
}

type userKeyshare struct {
	Message   MPCMessage `json:"message"` // BobOutput
	Role      int        `json:"role"`    // 2 for user, 1 for validator
	PublicKey []byte     `json:"public-key"`
}

func createUserKeyshare(out *dkg.BobOutput, msg MPCMessage) userKeyshare {
	return userKeyshare{
		Message:   msg,
		Role:      2,
		PublicKey: out.PublicKey.ToAffineUncompressed(),
	}
}

func (u userKeyshare) GetPayloads() map[string][]byte {
	return u.Message.Payloads
}

func (u userKeyshare) GetMetadata() map[string]string {
	return u.Message.Metadata
}

func (u userKeyshare) GetPublicKey() []byte {
	return u.PublicKey
}

func (u userKeyshare) GetProtocol() string {
	return u.Message.Protocol
}

func (u userKeyshare) GetRole() int32 {
	return int32(u.Role)
}

func (u userKeyshare) GetVersion() uint32 {
	return uint32(u.Message.Version)
}

func (u userKeyshare) Equals(o MPCShare) bool {
	return u.GetProtocol() == o.GetProtocol() &&
		u.GetVersion() == o.GetVersion() &&
		u.GetRole() == o.GetRole()
}

func (u userKeyshare) Marshal() (string, error) {
	jsonBytes, err := json.Marshal(u)
	return string(jsonBytes), err
}

func (u userKeyshare) Unmarshal(data string) error {
	return json.Unmarshal([]byte(data), &u)
}
