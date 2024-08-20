// / Crypto package
package crypto

import (
	"errors"
	"fmt"

	"github.com/onsonr/crypto/accumulator"
	"github.com/onsonr/crypto/core/curves"
)

// ZkAccumulator is the accumulator containing the elements
type ZkAccumulator = accumulator.Accumulator

// ZkElement is the element for the BLS scheme
type ZkElement = accumulator.Element

// ZkElements is the list of elements for the BLS scheme
type ZkElements = []accumulator.Element

// ZkPublicKey is the public key for the BLS scheme
type ZkPublicKey = accumulator.PublicKey

// ZkSecretKey is the secret key for the BLS scheme
type ZkSecretKey struct {
	*accumulator.SecretKey
}

// ZkWitness is the witness for the BLS scheme
type ZkWitness = accumulator.MembershipWitness

//
// Main Functions
//

// NewZkKey creates a new primary key
func NewZkKey(propertyKey string, pubKey []byte) (*ZkSecretKey, error) {
	// Concatenate the controller's public key and the property key
	input := append(pubKey, []byte(propertyKey)...)
	hash := []byte(input)

	// Use the hash as the seed for the secret key
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	key, err := new(accumulator.SecretKey).New(curve, hash[:])
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("failed to create secret key"))
	}
	return &ZkSecretKey{SecretKey: key}, nil
}

// LoadZkKey takes a byte slice and returns a *PrimaryKey
func LoadZkKey(data []byte) (*ZkSecretKey, error) {
	key := new(accumulator.SecretKey)
	err := key.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return &ZkSecretKey{SecretKey: key}, nil
}

// CreateAccumulator creates a new accumulator
func (s *ZkSecretKey) CreateAccumulator(values ...string) (*ZkAccumulator, error) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	acc, err := new(accumulator.Accumulator).New(curve)
	if err != nil {
		return nil, err
	}

	fin, _, err := acc.Update(s.SecretKey, ValuesToZkElements(values), nil)
	if err != nil {
		return nil, err
	}
	return fin, nil
}

// CreateWitness creates a witness for the accumulator for a given value
func (s *ZkSecretKey) CreateWitness(acc *ZkAccumulator, value string) (*ZkWitness, error) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	element := curve.Scalar.Hash([]byte(value))
	mw, err := new(accumulator.MembershipWitness).New(element, acc, s.SecretKey)
	if err != nil {
		return nil, err
	}
	return mw, nil
}

// ProveMembership proves that a value is a member of the accumulator
func (s *ZkSecretKey) VerifyWitness(acc *ZkAccumulator, witness *ZkWitness) error {
	return witness.Verify(s.PublicKey(), acc)
}

// PublicKey returns the public key for the secret key
func (s *ZkSecretKey) PublicKey() *ZkPublicKey {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	pk, err := s.GetPublicKey(curve)
	if err != nil {
		panic(err)
	}
	return pk
}

// UpdateAccumulator updates the accumulator with new values
func (s *ZkSecretKey) UpdateAccumulator(acc *ZkAccumulator, addValues []string, removeValues []string) (*ZkAccumulator, error) {
	acc, _, err := acc.Update(s.SecretKey, ValuesToZkElements(addValues), ValuesToZkElements(removeValues))
	if err != nil {
		return nil, err
	}
	return acc, nil
}

// MarshalAccumulator takes a *accumulator.Accumulator and returns a byte slice
func MarshalAccumulator(acc *ZkAccumulator) ([]byte, error) {
	return acc.MarshalBinary()
}

// UnmarshalAccumulator takes a byte slice and returns a *accumulator.Accumulator
func UnmarshalAccumulator(data []byte) (*accumulator.Accumulator, error) {
	acc := new(accumulator.Accumulator)
	err := acc.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

// MarshalWitness takes a *accumulator.MembershipWitness and returns a byte slice
func MarshalWitness(mw *accumulator.MembershipWitness) ([]byte, error) {
	return mw.MarshalBinary()
}

// UnmarshalWitness takes a byte slice and returns a *accumulator.MembershipWitness
func UnmarshalWitness(data []byte) (*accumulator.MembershipWitness, error) {
	mw := new(accumulator.MembershipWitness)
	err := mw.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return mw, nil
}

//
// Helper functions
//

// ValuesToZkElements converts a list of strings to a list of elements
func ValuesToZkElements(values []string) []accumulator.Element {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	elements := []accumulator.Element{}
	for _, value := range values {
		element := curve.Scalar.Hash([]byte(value))
		elements = append(elements, element)
	}
	return elements
}
