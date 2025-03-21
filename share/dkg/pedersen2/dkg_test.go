package pedersen2

import (
	"testing"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/s256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/tbls"
)

type Network struct {
	Generators []*DistKeyGenerator
	Suite      kyber.Group
	Nodes      []Node
}

func NewNetwork(t, n int) *Network {
	suite := s256.NewSuite()
	//nodeIdSuite := bn254.NewSuite()
	nodes := make([]Node, n)
	secrets := []kyber.Scalar{}
	for i := 0; i < n; i++ {
		// create secret
		nodeIdSecret := suite.Scalar().Pick(suite.RandomStream())
		secrets = append(secrets, nodeIdSecret)
		nodes[i] = Node{
			Index:  uint32(i),
			Public: suite.Point().Mul(nodeIdSecret, nil),
		}
	}
	generators := make([]*DistKeyGenerator, n)
	for i := 0; i < n; i++ {
		generators[i] = NewDistKeyGenerator(uint32(i), t, nodes, secrets[i])
	}
	return &Network{
		Generators: generators,
		Suite:      suite,
		Nodes:      nodes,
	}
}

func TestDKGNew(t *testing.T) {
	th := 3
	n := 5
	net := NewNetwork(th, n)
	bundles := make([]*DealBundle, n)
	for _, node := range net.Generators {
		if node == nil {
			t.Fatal("node is nil")
		}
		bundle, err := node.NewDKGDeal()
		if err != nil {
			t.Fatal(err)
		}
		bundles[node.idx] = bundle
	}

	distKeys := make([]*DistKeyShare, n)
	for _, gen := range net.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		distKey, err := gen.ProcessDealBundles(bundles)
		if err != nil {
			t.Fatal(err)
		}
		distKeys[gen.idx] = distKey

	}
	// make sure all public keys are the same
	pk := distKeys[1].Commits1[0]

	for _, dk := range distKeys {
		if !pk.Equal(dk.Commits1[0]) {
			t.Fatal("public key not equal")
		}
	}

	gen := net.Generators[0]
	scheme1 := tbls.NewThresholdSchemeOnG1(gen.suite[0])
	scheme2 := tbls.NewThresholdSchemeOnG1(gen.suite[1])
	msg := []byte("Hello BLS")
	sigShares1 := make([][]byte, 0)
	sigShares2 := make([][]byte, 0)
	for _, distKey := range distKeys {
		sig, err := scheme1.Sign(distKey.Share1, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares1 = append(sigShares1, sig)

		sig, err = scheme2.Sign(distKey.Share2, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares2 = append(sigShares2, sig)
	}
	priShares1 := make([]*share.PriShare, 0)
	for _, dk := range distKeys {
		priShares1 = append(priShares1, dk.Share1)
	}
	secretPoly, err := share.RecoverPriPoly(gen.suite[0].G2(), priShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	pubPolyExp := secretPoly.Commit(gen.suite[0].G2().Point().Base())
	pubPoly := share.NewPubPoly(gen.suite[0].G2(), nil, distKeys[1].Commits1)
	if !pubPoly.Equal(pubPolyExp) {
		t.Fatal("public key not equal")
	}

	sig, err := scheme1.Recover(pubPoly, msg, sigShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	err = scheme1.VerifyRecovered(pubPoly.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	pubPoly2 := share.NewPubPoly(gen.suite[1].G2(), nil, distKeys[1].Commits2)

	sig, err = scheme2.Recover(pubPoly2, msg, sigShares2, th, n)
	if err != nil {
		t.Fatal(err)
	}

	err = scheme2.VerifyRecovered(pubPoly2.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("BN254 public key: %v", pubPoly.Commit())
	t.Logf("BLS12-381 public key: %v", pubPoly2.Commit())
}

func TestDKGReshare(t *testing.T) {
	th := 3
	n := 5
	net := NewNetwork(th, n)
	bundles := make([]*DealBundle, n)
	for _, node := range net.Generators {
		if node == nil {
			t.Fatal("node is nil")
		}
		bundle, err := node.NewDKGDeal()
		if err != nil {
			t.Fatal(err)
		}
		bundles[node.idx] = bundle
	}

	distKeys := make([]*DistKeyShare, n)
	for _, gen := range net.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		distKey, err := gen.ProcessDealBundles(bundles)
		if err != nil {
			t.Fatal(err)
		}
		distKeys[gen.idx] = distKey

	}
	// make sure all public keys are the same
	pk := distKeys[1].Commits1[0]

	for _, dk := range distKeys {
		if !pk.Equal(dk.Commits1[0]) {
			t.Fatal("public key not equal")
		}
	}

	//tblScheme := bls.NewSchemeOnG1(nodeIdSuite)
	gen := net.Generators[0]
	scheme1 := tbls.NewThresholdSchemeOnG1(gen.suite[0])
	scheme2 := tbls.NewThresholdSchemeOnG1(gen.suite[1])
	msg := []byte("Hello BLS")
	sigShares1 := make([][]byte, 0)
	sigShares2 := make([][]byte, 0)
	for _, distKey := range distKeys {
		sig, err := scheme1.Sign(distKey.Share1, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares1 = append(sigShares1, sig)

		sig, err = scheme2.Sign(distKey.Share2, msg)
		if err != nil {
			t.Fatal(err)
		}
		sigShares2 = append(sigShares2, sig)
	}
	priShares1 := make([]*share.PriShare, 0)
	for _, dk := range distKeys {
		priShares1 = append(priShares1, dk.Share1)
	}
	secretPoly, err := share.RecoverPriPoly(gen.suite[0].G2(), priShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	pubPolyExp := secretPoly.Commit(gen.suite[0].G2().Point().Base())
	pubPoly := share.NewPubPoly(gen.suite[0].G2(), nil, distKeys[1].Commits1)
	if !pubPoly.Equal(pubPolyExp) {
		t.Fatal("public key not equal")
	}

	assertNoError(t, testSign(msg, distKeys, th, n))

	sig, err := scheme1.Recover(pubPoly, msg, sigShares1, th, n)
	if err != nil {
		t.Fatal(err)
	}
	err = scheme1.VerifyRecovered(pubPoly.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	pubPoly2 := share.NewPubPoly(gen.suite[1].G2(), nil, distKeys[1].Commits2)

	sig, err = scheme2.Recover(pubPoly2, msg, sigShares2, th, n)
	if err != nil {
		t.Fatal(err)
	}

	err = scheme2.VerifyRecovered(pubPoly2.Commit(), msg, sig)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("BN254 public key: %v", pubPoly.Commit())
	t.Logf("Post-reshare: BN254 pubPoly threshold %d", pubPoly.Threshold())

	t.Logf("BLS12-381 public key: %v", pubPoly2.Commit())

	// Reshare
	n2 := 10
	th2 := 8
	net2 := NewNetwork(th2, n2)
	bundles2 := make([]*DealBundle, 0)
	for _, gen := range net.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		bundle, err := gen.Reshare(distKeys[gen.idx], net2.Nodes, th2)
		if err != nil {
			t.Fatal(err)
		}
		bundles2 = append(bundles2, bundle)
	}
	distKeys2 := make([]*DistKeyShare, 0)
	for _, gen := range net2.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		distKey, err := gen.ProcessReshareDealBundles(bundles2, th, n)
		if err != nil {
			t.Fatal(err)
		}
		distKeys2 = append(distKeys2, distKey)
	}
	pubPoly2 = share.NewPubPoly(gen.suite[0].G2(), nil, distKeys2[1].Commits1)
	t.Logf("Post-reshare: BN254 public key: %v", pubPoly2.Commit())
	t.Logf("Post-reshare: BN254 pubPoly threshold %d", pubPoly2.Threshold())
	if !pubPoly2.Commit().Equal(pubPoly.Commit()) {
		t.Fatal("reshare failed; pubkey not the same after reshare")
	}
	{
		sigShares1 := make([][]byte, 0)
		for _, distKey := range distKeys2 {
			sig, err := scheme1.Sign(distKey.Share1, msg)
			if err != nil {
				t.Fatal(err)
			}
			sigShares1 = append(sigShares1, sig)
		}
		sig, err := scheme1.Recover(pubPoly2, msg, sigShares1, th2, n2)
		if err != nil {
			t.Fatal(err)
		}
		err = scheme1.VerifyRecovered(pubPoly2.Commit(), msg, sig)
		if err != nil {
			t.Fatal(err)
		}
	}

	// test one more reshare: reshare after reshare
	n3 := 6
	th3 := 5
	net3 := NewNetwork(th3, n3)
	bundles3 := make([]*DealBundle, 0)
	for _, gen := range net2.Generators {
		bundle, err := gen.Reshare(distKeys2[gen.idx], net3.Nodes, th3)
		assertNoError(t, err)
		bundles3 = append(bundles3, bundle)
	}
	distKeys3 := make([]*DistKeyShare, 0)
	for _, gen := range net3.Generators {
		if gen == nil {
			t.Fatal("gen is nil")
		}
		distKey, err := gen.ProcessReshareDealBundles(bundles3, th2, n2)
		if err != nil {
			t.Fatal(err)
		}
		distKeys3 = append(distKeys3, distKey)
	}
	pubPoly3 := share.NewPubPoly(gen.suite[0].G2(), nil, distKeys3[2].Commits1)
	t.Logf("Post-reshare2: BN254 public key: %v", pubPoly3.Commit())
	t.Logf("Post-reshare2: threshold: %d", pubPoly3.Threshold())
	if !pubPoly3.Commit().Equal(pubPoly2.Commit()) {
		t.Logf("reshare-reshare failed; pubkey changed")
	}

}

func testSign(msg []byte, distKeys []*DistKeyShare, th int, n int) error {
	scheme := distKeys[0].Scheme1
	tscheme := tbls.NewThresholdSchemeOnG1(scheme)

	sigShares := make([][]byte, 0)
	for _, distKey := range distKeys {
		sig, err := tscheme.Sign(distKey.Share1, msg)
		if err != nil {
			return err
		}
		sigShares = append(sigShares, sig)
	}
	pubPoly := share.NewPubPoly(scheme.G2(), nil, distKeys[0].Commits1)
	sig, err := tscheme.Recover(pubPoly, msg, sigShares, th, n)
	if err != nil {
		return err
	}
	err = tscheme.VerifyRecovered(pubPoly.Commit(), msg, sig)
	return err
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
