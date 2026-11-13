package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"golang.org/x/crypto/sha3"
)

func hashInput(target string, size int) []string {
	msg := make([]byte, size)
	for i := range msg {
		msg[i] = byte(i)
	}
	var digest []byte
	if target == "sha256" {
		sum := sha256.Sum256(msg)
		digest = sum[:]
	} else {
		h := sha3.NewLegacyKeccak256()
		h.Write(msg)
		digest = h.Sum(nil)
	}
	return []string{hex.EncodeToString(msg), hex.EncodeToString(digest)}
}

func signatureInput(t *testing.T) []string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("gnark benchmark input"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []string{hex.EncodeToString(digest[:]), fmt.Sprintf("%064x", key.X), fmt.Sprintf("%064x", key.Y), fmt.Sprintf("%064x%064x", r, s)}
}

// Check our input conversion, public/private tags and digest constraints.
func TestCircuits(t *testing.T) {
	cases := []struct {
		target string
		size   int
		input  []string
		public int
	}{
		{"sha256", 128, hashInput("sha256", 128), 32},
		{"sha256", 256, hashInput("sha256", 256), 32},
		{"keccak", 128, hashInput("keccak", 128), 32},
		{"keccak", 256, hashInput("keccak", 256), 32},
		{"poseidon2", 2, []string{"1", "2"}, 1},
		{"poseidon2", 8, []string{"1", "2", "3", "4", "5", "6", "7", "8"}, 1},
		{"ecdsa", 32, signatureInput(t), 12},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%d", tc.target, tc.size), func(t *testing.T) {
			shape, assignment, err := circuits(tc.target, tc.size, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
			if err != nil {
				t.Fatal(err)
			}
			solve := func() error {
				w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
				if err != nil {
					return err
				}
				return ccs.IsSolved(w)
			}
			if err := solve(); err != nil {
				t.Fatal(err)
			}
			public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
			if err != nil {
				t.Fatal(err)
			}
			if got := len(public.Vector().(fr.Vector)); got != tc.public {
				t.Fatalf("public witness has %d elements, want %d", got, tc.public)
			}
			switch a := assignment.(type) {
			case *hashCircuit:
				digest, _ := hex.DecodeString(tc.input[1])
				a.Digest[0] = uints.NewU8(digest[0] ^ 1)
			case *poseidonCircuit:
				a.Digest = new(big.Int).Add(a.Digest.(*big.Int), big.NewInt(1))
			case *ecdsaCircuit:
				a.Digest = emulated.ValueOf[emulated.P256Fr](0)
			}
			if err := solve(); err == nil {
				t.Fatal("accepted a changed public digest")
			}
			_, assignment, err = circuits(tc.target, tc.size, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			switch a := assignment.(type) {
			case *hashCircuit:
				a.Input[0] = uints.NewU8(255)
			case *poseidonCircuit:
				a.Input[0] = 99
			case *ecdsaCircuit:
				a.Signature.R = emulated.ValueOf[emulated.P256Fr](0)
			}
			if err := solve(); err == nil {
				t.Fatal("accepted changed private input")
			}
		})
	}
}

func TestArtifactFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	sizes, counts := filepath.Join(dir, "sizes.json"), filepath.Join(dir, "counts.json")
	if err := prepare(path, "poseidon2", 2, []string{"1", "2"}); err != nil {
		t.Fatal(err)
	}
	if err := measure(path, sizes, counts); err != nil {
		t.Fatal(err)
	}
	if err := verify(path); err != nil {
		t.Fatal(err)
	}
	var measured map[string]int64
	b, err := os.ReadFile(sizes)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &measured); err != nil {
		t.Fatal(err)
	}
	if measured["proof_size"] <= 0 || measured["preprocessing_size"] <= 0 {
		t.Fatal(measured)
	}
	var constraints map[string]map[string]int
	b, err = os.ReadFile(counts)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &constraints); err != nil {
		t.Fatal(err)
	}
	if constraints["poseidon2"]["2"] <= 0 {
		t.Fatal(constraints)
	}
	for _, suffix := range []string{"", ".r1cs", ".pk"} {
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := verify(path); err != nil {
		t.Fatalf("verification needs private prover artifacts: %v", err)
	}
	_, assignment, err := circuits("poseidon2", 2, []string{"2", "3"})
	if err != nil {
		t.Fatal(err)
	}
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeArtifact(path+".public", public); err != nil {
		t.Fatal(err)
	}
	if err := verify(path); err == nil {
		t.Fatal("verified proof with a changed public digest")
	}
}

func TestInvalidInputs(t *testing.T) {
	for _, tc := range []struct {
		target string
		size   int
		input  []string
	}{
		{"unknown", 2, nil}, {"sha256", 0, nil}, {"sha256", 128, []string{"00", "00"}},
		{"keccak", 128, []string{"zz", "00"}}, {"poseidon2", 2, []string{"1"}},
		{"poseidon2", 2, []string{"-1", "2"}}, {"poseidon2", 2, []string{ecc.BN254.ScalarField().String(), "2"}},
		{"ecdsa", 32, []string{"00", "00", "00", "00"}},
	} {
		if _, _, err := circuits(tc.target, tc.size, tc.input); err == nil {
			t.Errorf("accepted invalid input: %+v", tc)
		}
	}
}
