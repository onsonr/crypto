package crypto

import (
	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
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
type MPCMessage = protocol.Message

type MPCSignature *curves.EcdsaSignature

type MPCShare interface {
	Equals(o MPCShare) bool
	GetPayloads() map[string][]byte
	GetMetadata() map[string]string
	GetPublicKey() []byte
	GetProtocol() string
	GetRole() int
	GetVersion() uint
}

// RefreshFunc is the type for the refresh function
type RefreshFunc interface {
	protocol.Iterator
}

// SignFunc is the type for the sign function
type SignFunc interface {
	protocol.Iterator
}
