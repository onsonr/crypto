package mpc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/onsonr/crypto/core/protocol"
)

var ErrInvalidKeyshareRole = errors.New("invalid keyshare role")

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
