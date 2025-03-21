package pedersen2

import (
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/encrypt/ecies"
	"go.dedis.ch/kyber/v4/group/s256"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/pairing/bls12381/kilic"
	"go.dedis.ch/kyber/v4/pairing/bn254"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/util/random"
)

// this package is based on the pedersen package in the same directory
// It aims to simplify the protocol, especially remove the eviction, and the
// dynamic QUALified nodes; essentially the protocol aborts if one mandated node
// fails, or if any complaint is reported. This model is more appropriate for
// use where the set of participating nodes are managed elsewhere.

// The protocol has two operations: KeyGen, and ReShare.
// KeyGen protocol: (t-n)-threshold DKG protocol
// 1. Each node generates a random secret and prepare to VSS it with all signers.
// 2. Each node generate a share of the secret for each other node, and a commitment.
// 3. Each node sends the (encrypted) share and commitment to all other nodes.
// 4. Each node verifies the shares and commitments, and if all are valid, the node
//    stores the shares and commitments.
// 5. If any node fails to verify, the protocol aborts.
// 6. If all nodes verify, the protocol completes and the nodes have a distributed
//    key share. Each node can then generate a public key from the shares.

// The communication between the nodes are in a broadcast channel that guarantees
// that all nodes receive the same messages.

// ReShare protocol: (t-n)-threshold DKG protocol
// TODO

type DistKeyGenerator struct {
	state State

	// the following are for authenticating keygen signers; should be on S256 (secp256k1) curve
	// This is because zetachain already uses secp256k1 for signing txs and node ID is based on operator wallet address
	nodeIdSuite  Suite
	nodeIdSecret kyber.Scalar
	nodeIdPublic kyber.Point
	nodes        []Node // all signing nodes in the network
	idx          uint32 // node index; significant as it's the x in lagrange interpolation
	threshold    int    // threshold+1 is the number of nodes needed to reconstruct the secret

	// two curves: BN254 and BLS12-381
	suite       [2]pairing.Suite
	dpriv       [2]*share.PriPoly
	dpub        [2]*share.PubPoly
	validShares [2]map[uint32]kyber.Scalar
	allPublics  [2]map[uint32]*share.PubPoly

	// curve 2: BLS12-381
	//suite2       pairing.Suite
	//dpriv2       *share.PriPoly
	//dpub2        *share.PubPoly
	//validShares2 map[uint32]kyber.Scalar
	//allPublics2  map[uint32]*share.PubPoly
}

// If new DKG, this function will create the secret s (dpriv1) and populate the field in result
func NewDistKeyGenerator(idx uint32, threshold int, nodes []Node, nodeIdSecret kyber.Scalar) *DistKeyGenerator {
	suiteId := s256.NewSuite()
	suite1 := bn254.NewSuite()
	suite2 := kilic.NewSuiteBLS12381()

	randomStream := random.New()
	// make sure that the secret fits in the  smaller curve BN254
	secretCoeff1 := suite1.G2().Scalar().Pick(randomStream)
	secretCoeff2 := suite2.G2().Scalar().Pick(randomStream)
	dpriv1 := share.NewPriPoly(suite1.G2(), threshold, secretCoeff1, randomStream)
	dpub1 := dpriv1.Commit(suite1.G2().Point().Base())
	dpriv2 := share.NewPriPoly(suite2.G2(), threshold, secretCoeff2, randomStream)
	dpub2 := dpriv2.Commit(suite2.G2().Point().Base())

	return &DistKeyGenerator{
		state:        InitState,
		nodeIdSuite:  suiteId,
		nodeIdSecret: nodeIdSecret,
		nodeIdPublic: suiteId.Point().Mul(nodeIdSecret, nil),
		nodes:        nodes,
		idx:          idx,
		threshold:    threshold,
		suite:        [2]pairing.Suite{suite1, suite2},
		dpriv:        [2]*share.PriPoly{dpriv1, dpriv2},
		dpub:         [2]*share.PubPoly{dpub1, dpub2},
		validShares:  [2]map[uint32]kyber.Scalar{make(map[uint32]kyber.Scalar), make(map[uint32]kyber.Scalar)},
		allPublics:   [2]map[uint32]*share.PubPoly{make(map[uint32]*share.PubPoly), make(map[uint32]*share.PubPoly)},
	}
}

// Deal is the first phase of the DKG protocol where the node creates VSS shares and commits
// each node should call this Deal and generate a DealBundle for other nodes (broadcast is fine
// as recipient needs to decrypt their share)
func (gen *DistKeyGenerator) NewDKGDeal() (*DealBundle, error) {
	deals := make([]Deal, 0, len(gen.nodes))

	for _, node := range gen.nodes {
		// compute share
		si1 := gen.dpriv[0].Eval(node.Index).V
		si2 := gen.dpriv[1].Eval(node.Index).V
		msg1, _ := si1.MarshalBinary()
		msg2, _ := si2.MarshalBinary()
		cipher1, err := ecies.Encrypt(gen.nodeIdSuite, node.Public, msg1, nil)
		if err != nil {
			return nil, err
		}
		cipher2, err := ecies.Encrypt(gen.nodeIdSuite, node.Public, msg2, nil)
		if err != nil {
			return nil, err
		}
		deals = append(deals, Deal{
			ShareIndex:      node.Index,
			EncryptedShare1: cipher1,
			EncryptedShare2: cipher2,
		})
	}
	_, commits1 := gen.dpub[0].Info()
	_, commits2 := gen.dpub[1].Info()
	return &DealBundle{
		DealerIndex: gen.idx,
		Deals:       deals,
		Public1:     commits1,
		Public2:     commits2,
		SessionID:   []byte("session-id"),
		Signature:   nil, // no need to sign as the bundle submission is via a tx which already needs to signed.
	}, nil
	//return nil, fmt.Errorf("CANNOT REACH HERE")
}

// When all bundles are available, then process all bundles, compute the local private share,
// and return the public key share
func (gen *DistKeyGenerator) ProcessDealBundles(bundles []*DealBundle) (*DistKeyShare, error) {
	if len(bundles) != len(gen.nodes) {
		return nil, fmt.Errorf("DKG: can't process deal bundles because len(bundles) != len(nodes); need all nodes to submit their deals")
	}
	for _, bundle := range bundles {
		gen.allPublics[0][bundle.DealerIndex] = share.NewPubPoly(gen.suite[0].G2(), nil, bundle.Public1)
		gen.allPublics[1][bundle.DealerIndex] = share.NewPubPoly(gen.suite[1].G2(), nil, bundle.Public2)
	}
	finalShare1 := gen.suite[0].G2().Scalar().Zero()
	finalShare2 := gen.suite[1].G2().Scalar().Zero()
	var err error
	var finalPub1 *share.PubPoly
	var finalPub2 *share.PubPoly
	for _, n := range gen.nodes {
		bundle := bundles[n.Index]
		for _, deal := range bundle.Deals {
			if deal.ShareIndex != gen.idx {
				continue
			}
			plain1, err := ecies.Decrypt(gen.nodeIdSuite, gen.nodeIdSecret, deal.EncryptedShare1, nil)
			if err != nil {
				return nil, err
			}
			sh := gen.suite[0].G2().Scalar().SetBytes(plain1)
			gen.validShares[0][bundle.DealerIndex] = sh

			plain2, err := ecies.Decrypt(gen.nodeIdSuite, gen.nodeIdSecret, deal.EncryptedShare2, nil)
			if err != nil {
				return nil, err
			}
			sh = gen.suite[1].G2().Scalar().SetBytes(plain2)
			gen.validShares[1][bundle.DealerIndex] = sh
		}
		sh1, ok := gen.validShares[0][n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: private share (BN254) not found from dealer %d", n.Index)
		}
		sh2, ok := gen.validShares[1][n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: private share (BLS12-381) not found from dealer %d", n.Index)
		}

		pub1, ok := gen.allPublics[0][n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: idx %d public BN254 polynomial not found from dealer %d", gen.idx, n.Index)
		}
		pub2, ok := gen.allPublics[1][n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: idx %d public BLS12-381 polynomial not found from dealer %d", gen.idx, n.Index)
		}
		// check if share is valid w.r.t. public commitment
		comm := pub1.Eval(gen.idx).V
		commShare := gen.suite[0].G2().Point().Mul(sh1, nil)
		if !comm.Equal(commShare) {
			return nil, fmt.Errorf("Deal share invalid wrt public poly (BN254)")
		}
		comm = pub2.Eval(gen.idx).V
		commShare = gen.suite[1].G2().Point().Mul(sh2, nil)
		if !comm.Equal(commShare) {
			return nil, fmt.Errorf("Deal share invalid wrt public poly (BLS12-381)")
		}
		finalShare1 = finalShare1.Add(finalShare1, sh1)
		finalShare2 = finalShare2.Add(finalShare2, sh2)

		if finalPub1 == nil {
			finalPub1 = pub1
		} else {
			finalPub1, err = finalPub1.Add(pub1)
			if err != nil {
				return nil, err
			}
		}
		if finalPub2 == nil {
			finalPub2 = pub2
		} else {
			finalPub2, err = finalPub2.Add(pub2)
			if err != nil {
				return nil, err
			}
		}

	}
	if finalPub1 == nil {
		return nil, fmt.Errorf("BUG: final public1 polynomial is nil")
	}
	if finalPub2 == nil {
		return nil, fmt.Errorf("BUG: final public2 polynomial is nil")
	}
	_, commits1 := finalPub1.Info()
	_, commits2 := finalPub2.Info()
	return &DistKeyShare{
		Scheme1:  gen.suite[0],
		Scheme2:  gen.suite[1],
		Commits1: commits1,
		Commits2: commits2,
		Share1:   &share.PriShare{I: gen.idx, V: finalShare1},
		Share2:   &share.PriShare{I: gen.idx, V: finalShare2},
	}, nil
}

// the old nodes must call this function to initiate a re-share operation;
// must have > old threshold nodes to call this function
func (gen *DistKeyGenerator) Reshare(distKeyShare *DistKeyShare, newNodes []Node, newT int) (*DealBundle, error) {
	// now start the re-share. The existing ndoe will generate new shares for the new nodes and
	// create deal bundles. The public key should not change.
	// The new nodes will receive the deal bundles and process them to get the new shares.
	// The new nodes will then have the new shares and the public key.
	randomStream := random.New()
	dpriv1 := share.NewPriPoly(gen.suite[0].G2(), newT, distKeyShare.Share1.V, randomStream)
	dpub1 := dpriv1.Commit(gen.suite[0].G2().Point().Base())
	gen.dpriv[0] = dpriv1
	gen.dpub[0] = dpub1

	deals := make([]Deal, 0, len(newNodes))
	// generate a deal for each new node
	for _, node := range newNodes {
		// compute share
		si1 := gen.dpriv[0].Eval(node.Index).V
		si2 := gen.dpriv[1].Eval(node.Index).V
		msg1, _ := si1.MarshalBinary()
		msg2, _ := si2.MarshalBinary()
		cipher1, err := ecies.Encrypt(gen.nodeIdSuite, node.Public, msg1, nil)
		if err != nil {
			return nil, err
		}
		cipher2, err := ecies.Encrypt(gen.nodeIdSuite, node.Public, msg2, nil)
		if err != nil {
			return nil, err
		}
		deals = append(deals, Deal{
			ShareIndex:      node.Index,
			EncryptedShare1: cipher1,
			EncryptedShare2: cipher2,
		})
	}
	_, commits1 := gen.dpub[0].Info()
	_, commits2 := gen.dpub[1].Info()
	return &DealBundle{
		DealerIndex: gen.idx,
		Deals:       deals,
		Public1:     commits1,
		Public2:     commits2,
		SessionID:   []byte("session-id"),
		Signature:   nil, // no need to sign as the bundle submission is via a tx which already needs to signed.
	}, nil

}

// When all bundles are available, then process all bundles, compute the local private share,
// and return the public key share
func (gen *DistKeyGenerator) ProcessReshareDealBundles(bundles []*DealBundle, oldT int, oldN int) (*DistKeyShare, error) {
	shares := make([]*share.PriShare, 0, oldN)
	coeffs := make(map[uint32][]kyber.Point, oldN)

	dealsForMe := make([]Deal, 0)
	for _, bundle := range bundles {
		if bundle == nil {
			return nil, fmt.Errorf("Node %d received nil bundle\n", gen.idx)
		}
		coeffs[bundle.DealerIndex] = bundle.Public1
		for _, deal := range bundle.Deals {
			if deal.ShareIndex == gen.idx {
				dealsForMe = append(dealsForMe, deal)
				plain, err := ecies.Decrypt(gen.nodeIdSuite, gen.nodeIdSecret, deal.EncryptedShare1, nil)
				if err != nil {
					return nil, err
				}
				sh := gen.suite[0].G2().Scalar().SetBytes(plain)
				shares = append(shares, &share.PriShare{I: bundle.DealerIndex, V: sh})
			}
		}
	}

	priPoly, err := share.RecoverPriPoly(gen.suite[0].G2(), shares, oldT, oldN)
	if err != nil {
		return nil, err
	}
	privateShare := &share.PriShare{
		I: gen.idx,
		V: priPoly.Secret(),
	}
	newT := gen.threshold
	finalCoeffs := make([]kyber.Point, newT)
	for i := 0; i < newT; i++ {
		tmpCoeffs := make([]*share.PubShare, 0, oldN)
		for j := range coeffs {
			tmpCoeffs = append(tmpCoeffs, &share.PubShare{I: j, V: coeffs[j][i]})
		}
		coeff, err := share.RecoverCommit(gen.suite[0].G2(), tmpCoeffs, oldT, oldN)
		if err != nil {
			return nil, err
		}
		finalCoeffs[i] = coeff
	}
	pubPoly := share.NewPubPoly(gen.suite[0].G2(), nil, finalCoeffs)
	if !pubPoly.Check(privateShare) {
		return nil, fmt.Errorf("Node %d: public polynomial check failed", gen.idx)
	}
	return &DistKeyShare{
		Scheme1:  gen.suite[0],
		Commits1: finalCoeffs,
		//Commits2: commits2,
		//Share1:   &share.PriShare{I: gen.idx, V: finalShare1},
		Share1: privateShare,
		//Share2:   &share.PriShare{I: gen.idx, V: finalShare2},
	}, nil
}
