package pedersen2

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/share"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// Phase is a type that represents the different stages of the DKG protocol.
type State int

const (
	InitState State = iota
	DealState
	FinishState
	AbortState
)

func (p State) String() string {
	switch p {
	case InitState:
		return "init"
	case DealState:
		return "deal"
	case FinishState:
		return "finish"
	case AbortState:
		return "abort"
	}
	return "unknown"
}

type Node struct {
	Index  uint32
	Public kyber.Point
}

type DealBundle struct {
	DealerIndex uint32
	// BN254 deals
	Deals []Deal

	// BN254 Public coefficients of the public polynomial used to create the shares
	Public1 []kyber.Point
	// BLS12-381 Public coefficients of the public polynomial used to create the shares
	Public2 []kyber.Point
	// SessionID of the current run
	SessionID []byte
	// Signature over the hash of the whole bundle
	Signature []byte
}

type Deal struct {
	// Index of the share holder
	ShareIndex uint32
	// encrypted share issued to the share holder
	EncryptedShare1 []byte // BN254
	// encrypted share issued to the share holder
	EncryptedShare2 []byte // BLS12-381
}

type DistKeyShare struct {
	Scheme1  pairing.Suite
	Scheme2  pairing.Suite
	Commits1 []kyber.Point // BN254
	Commits2 []kyber.Point // BLS12-381
	Share1   *share.PriShare
	Share2   *share.PriShare
}
