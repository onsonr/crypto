package crypto

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
	"golang.org/x/crypto/sha3"
)

// GetMPCMessage returns the protocol.Message for the keyshare
func GetMPCMessage(k MPCShare) *protocol.Message {
	return &protocol.Message{
		Payloads: k.GetPayloads(),
		Metadata: k.GetMetadata(),
		Protocol: k.GetProtocol(),
		Version:  k.GetVersion(),
	}
}

// GetRawPublicKey is the public key for the keyshare
func GetRawPublicKey(ks MPCShare) ([]byte, error) {
	role := MPCRole(ks.GetRole())
	if role.IsUser() {
		bobOut, err := dklsv1.DecodeBobDkgResult(GetMPCMessage(ks))
		if err != nil {
			return nil, err
		}
		return bobOut.PublicKey.ToAffineUncompressed(), nil
	} else if role.IsValidator() {
		aliceOut, err := dklsv1.DecodeAliceDkgResult(GetMPCMessage(ks))
		if err != nil {
			return nil, err
		}
		return aliceOut.PublicKey.ToAffineUncompressed(), nil
	}
	return nil, ErrInvalidKeyshareRole
}

// GetECDSAPublicKey is the public key for the keyshare
func GetECDSAPublicKey(ks MPCShare) (*ecdsa.PublicKey, error) {
	raw, err := GetRawPublicKey(ks)
	if err != nil {
		return nil, err
	}
	return ComputeEcdsaPublicKey(raw)
}

// GetRefreshFunc returns the refresh function for the keyshare
func GetRefreshFunc(ks MPCShare) (RefreshFunc, error) {
	curve := curves.K256()
	role := MPCRole(ks.GetRole())
	if role.IsUser() {
		return dklsv1.NewBobRefresh(curve, GetMPCMessage(ks), protocol.Version1)
	} else if role.IsValidator() {
		return dklsv1.NewAliceRefresh(curve, GetMPCMessage(ks), protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

// GetSignFunc returns the sign function for the keyshare
func GetSignFunc(ks MPCShare, msg []byte) (SignFunc, error) {
	curve := curves.K256()
	role := MPCRole(ks.GetRole())
	if role.IsUser() {
		return dklsv1.NewBobSign(curve, sha3.New256(), msg, GetMPCMessage(ks), protocol.Version1)
	} else if role.IsValidator() {
		return dklsv1.NewAliceSign(curve, sha3.New256(), msg, GetMPCMessage(ks), protocol.Version1)
	}
	return nil, ErrInvalidKeyshareRole
}

// RunMPCGenerate generates a new MPC keyshare
func RunMPCGenerate() ([]MPCShare, error) {
	curve := curves.K256()
	valKs := dklsv1.NewAliceDkg(curve, protocol.Version1)
	userKs := dklsv1.NewBobDkg(curve, protocol.Version1)
	aErr, bErr := runIteratedProtocol(valKs, userKs)
	if aErr != protocol.ErrProtocolFinished {
		return nil, aErr
	}
	if bErr != protocol.ErrProtocolFinished {
		return nil, bErr
	}
	valRes, err := valKs.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	userRes, err := userKs.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}

	return createKeyshareArray(valRes, userRes)
}

// RunMPCSign runs the MPC signing protocol
func RunMPCSign(signFuncVal SignFunc, signFuncUser SignFunc) (MPCSignature, error) {
	aErr, bErr := runIteratedProtocol(signFuncVal, signFuncUser)
	if aErr != protocol.ErrProtocolFinished {
		return nil, aErr
	}
	if bErr != protocol.ErrProtocolFinished {
		return nil, bErr
	}
	out, err := signFuncUser.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	return dklsv1.DecodeSignature(out)
}

// RunMPCRefresh runs the MPC refresh protocol
func RunMPCRefresh(refreshFuncVal RefreshFunc, refreshFuncUser RefreshFunc) ([]MPCShare, error) {
	aErr, bErr := runIteratedProtocol(refreshFuncVal, refreshFuncUser)
	if aErr != protocol.ErrProtocolFinished {
		return nil, aErr
	}
	if bErr != protocol.ErrProtocolFinished {
		return nil, bErr
	}
	valRefreshResult, err := refreshFuncVal.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	userRefreshResult, err := refreshFuncUser.Result(protocol.Version1)
	if err != nil {
		return nil, err
	}
	return createKeyshareArray(valRefreshResult, userRefreshResult)
}

// SerializeSecp256k1Signature serializes an ECDSA signature into a byte slice
func SerializeMPCSignature(sig MPCSignature) ([]byte, error) {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	sigBytes := make([]byte, 66) // V (1 byte) + R (32 bytes) + S (32 bytes)
	sigBytes[0] = byte(sig.V)
	copy(sigBytes[33-len(rBytes):33], rBytes)
	copy(sigBytes[66-len(sBytes):66], sBytes)
	return sigBytes, nil
}

// DeserializeSecp256k1Signature deserializes an ECDSA signature from a byte slice
func DeserializeMPCSignature(sigBytes []byte) (MPCSignature, error) {
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
func VerifyMPCSignature(sig MPCSignature, msg []byte, publicKey *ecdsa.PublicKey) bool {
	return ecdsa.Verify(publicKey, msg, sig.R, sig.S)
}
