package mpc

import (
	"github.com/onsonr/crypto/core/curves"
	"github.com/onsonr/crypto/core/protocol"
	"github.com/onsonr/crypto/tecdsa/dklsv1"
)

// GenerateKeyshares generates a new MPC keyshare
func GenerateKeyshares() ([]Share, error) {
	curve := curves.K256()
	valKs := dklsv1.NewAliceDkg(curve, protocol.Version1)
	userKs := dklsv1.NewBobDkg(curve, protocol.Version1)
	aErr, bErr := RunProtocol(valKs, userKs)
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
	return NewKeyshareArray(valRes, userRes)
}

// RunSignProtocol runs the MPC signing protocol
func RunSignProtocol(signFuncVal SignFunc, signFuncUser SignFunc) (Signature, error) {
	aErr, bErr := RunProtocol(signFuncVal, signFuncUser)
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

// RunRefreshProtocol runs the MPC refresh protocol
func RunRefreshProtocol(refreshFuncVal RefreshFunc, refreshFuncUser RefreshFunc) ([]Share, error) {
	aErr, bErr := RunProtocol(refreshFuncVal, refreshFuncUser)
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
	return NewKeyshareArray(valRefreshResult, userRefreshResult)
}

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
