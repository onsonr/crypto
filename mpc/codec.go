package mpc

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
)

var ErrInvalidKeyshareRole = errors.New("invalid keyshare role")

// ╭───────────────────────────────────────────────────────────╮
// │                   General Type Aliases                    │
// ╰───────────────────────────────────────────────────────────╯

// Message is the protocol.Message that is used for MPC
type Message *protocol.Message

// PublicKey
type PublicKey *ecdsa.PublicKey

type Signature *curves.EcdsaSignature

// RefreshFunc is the type for the refresh function
type RefreshFunc interface{ protocol.Iterator }

// SignFunc is the type for the sign function
type SignFunc interface{ protocol.Iterator }

// ╭───────────────────────────────────────────────────────────╮
// │                     Enumeration Roles                     │
// ╰───────────────────────────────────────────────────────────╯

type Role string

const (
	RoleUser      Role = "user"
	RoleValidator Role = "validator"
)

func ExtractRole(s string) (Role, error) {
	ptrs := strings.Split(s, ":")
	if len(ptrs) != 2 {
		return "", errors.New("malformed keyshare")
	}
	r := Role(ptrs[0])
	if r.IsBob() || r.IsAlice() {
		return r, nil
	}
	return "", ErrInvalidKeyshareRole
}

func (r Role) String() string {
	return string(r)
}

func (r Role) IsBob() bool {
	return r == RoleUser
}

func (r Role) IsAlice() bool {
	return r == RoleValidator
}

// ╭───────────────────────────────────────────────────────╮
// │                  Keyshare Management                  │
// ╰───────────────────────────────────────────────────────╯

func NewKeyshareArray(val Message, user Message) ([]Share, error) {
	valShare, err := EncodeKeyshare(val, RoleValidator)
	if err != nil {
		return nil, err
	}
	userShare, err := EncodeKeyshare(user, RoleUser)
	if err != nil {
		return nil, err
	}
	return []Share{
		valShare,
		userShare,
	}, nil
}

// EncodeKeyshare encodes the message to a string.
func EncodeKeyshare(msg Message, role Role) (Share, error) {
	ks, err := protocol.EncodeMessage(msg)
	if err != nil {
		return "", err
	}
	return Share(fmt.Sprintf("%s:%s", role.String(), ks)), nil
}

// DecodeKeyshare decodes the message from a string.
func DecodeKeyshare(s string) (Share, error) {
	ptrs := strings.Split(s, ":")
	if len(ptrs) != 2 {
		return "", errors.New("malformed keyshare")
	}
	_, err := ExtractRole(ptrs[0])
	if err != nil {
		return "", err
	}
	_, err = protocol.DecodeMessage(ptrs[1])
	if err != nil {
		return "", err
	}
	return Share(s), nil
}

// ╭───────────────────────────────────────────────────────╮
// │                  Signatures (ECDSA)                   │
// ╰───────────────────────────────────────────────────────╯

// SerializeSecp256k1Signature serializes an ECDSA signature into a byte slice
func SerializeSignature(sig Signature) ([]byte, error) {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	sigBytes := make([]byte, 66) // V (1 byte) + R (32 bytes) + S (32 bytes)
	sigBytes[0] = byte(sig.V)
	copy(sigBytes[33-len(rBytes):33], rBytes)
	copy(sigBytes[66-len(sBytes):66], sBytes)
	return sigBytes, nil
}

// DeserializeSecp256k1Signature deserializes an ECDSA signature from a byte slice
func DeserializeSignature(sigBytes []byte) (Signature, error) {
	if len(sigBytes) != 66 {
		return nil, errors.New("malformed signature: not the correct size")
	}
	sig := &curves.EcdsaSignature{
		V: int(sigBytes[0]),
		R: new(big.Int).SetBytes(sigBytes[1:33]),
		S: new(big.Int).SetBytes(sigBytes[33:66]),
	}
	return sig, nil
}

// VerifyMPCSignature verifies an MPC signature
func VerifyMPCSignature(sig Signature, msg []byte, publicKey *ecdsa.PublicKey) bool {
	return ecdsa.Verify(publicKey, msg, sig.R, sig.S)
}
