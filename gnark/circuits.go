package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativeposeidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

type hashCircuit struct {
	Input  []uints.U8
	Digest [32]uints.U8 `gnark:",public"`
	Keccak bool         `gnark:"-"`
}

func (c *hashCircuit) Define(api frontend.API) error {
	var h hash.BinaryHasher
	var err error
	if c.Keccak {
		h, err = sha3.NewLegacyKeccak256(api)
	} else {
		h, err = sha2.New(api)
	}
	if err != nil {
		return err
	}
	h.Write(c.Input)
	bytes, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for i, v := range h.Sum() {
		bytes.AssertIsEqual(v, c.Digest[i])
	}
	return nil
}

type poseidonCircuit struct {
	Input  []frontend.Variable
	Digest frontend.Variable `gnark:",public"`
}

func (c *poseidonCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(c.Input...)
	api.AssertIsEqual(h.Sum(), c.Digest)
	return nil
}

type ecdsaCircuit struct {
	Signature ecdsa.Signature[emulated.P256Fr]
	Digest    emulated.Element[emulated.P256Fr]                 `gnark:",public"`
	PublicKey ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] `gnark:",public"`
}

func (c *ecdsaCircuit) Define(api frontend.API) error {
	c.PublicKey.Verify(api, sw_emulated.GetCurveParams[emulated.P256Fp](), &c.Digest, &c.Signature)
	return nil
}

func decodeHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("expected %d bytes, got %d", size, len(b))
	}
	return b, nil
}

// circuits translates the shared utils input format into a circuit and assignment.
func circuits(target string, size int, input []string) (frontend.Circuit, frontend.Circuit, error) {
	if size <= 0 {
		return nil, nil, fmt.Errorf("input size must be positive")
	}
	switch target {
	case "sha256", "keccak":
		if len(input) != 2 {
			return nil, nil, fmt.Errorf("expected message and digest")
		}
		msg, err := decodeHex(input[0], size)
		if err != nil {
			return nil, nil, err
		}
		digest, err := decodeHex(input[1], 32)
		if err != nil {
			return nil, nil, err
		}
		shape := &hashCircuit{Input: make([]uints.U8, size), Keccak: target == "keccak"}
		assignment := &hashCircuit{Input: uints.NewU8Array(msg), Keccak: shape.Keccak}
		copy(assignment.Digest[:], uints.NewU8Array(digest))
		return shape, assignment, nil
	case "poseidon2":
		if len(input) != size {
			return nil, nil, fmt.Errorf("expected %d field elements", size)
		}
		assignment := &poseidonCircuit{Input: make([]frontend.Variable, size)}
		h := nativeposeidon.NewMerkleDamgardHasher()
		for i, s := range input {
			value, ok := new(big.Int).SetString(s, 10)
			if !ok || value.Sign() < 0 || value.Cmp(fr.Modulus()) >= 0 {
				return nil, nil, fmt.Errorf("invalid BN254 field element at %d", i)
			}
			assignment.Input[i] = value
			var element fr.Element
			element.SetBigInt(value)
			b := element.Bytes()
			if _, err := h.Write(b[:]); err != nil {
				return nil, nil, err
			}
		}
		assignment.Digest = new(big.Int).SetBytes(h.Sum(nil))
		return &poseidonCircuit{Input: make([]frontend.Variable, size)}, assignment, nil
	case "ecdsa":
		if size != 32 || len(input) != 4 {
			return nil, nil, fmt.Errorf("expected a 32-byte digest, P-256 public key coordinates and signature")
		}
		values := make([]*big.Int, 3)
		for i := range values {
			b, err := decodeHex(input[i], 32)
			if err != nil {
				return nil, nil, err
			}
			values[i] = new(big.Int).SetBytes(b)
		}
		sig, err := decodeHex(input[3], 64)
		if err != nil {
			return nil, nil, err
		}
		return &ecdsaCircuit{}, &ecdsaCircuit{
			Digest:    emulated.ValueOf[emulated.P256Fr](values[0]),
			PublicKey: ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{X: emulated.ValueOf[emulated.P256Fp](values[1]), Y: emulated.ValueOf[emulated.P256Fp](values[2])},
			Signature: ecdsa.Signature[emulated.P256Fr]{R: emulated.ValueOf[emulated.P256Fr](new(big.Int).SetBytes(sig[:32])), S: emulated.ValueOf[emulated.P256Fr](new(big.Int).SetBytes(sig[32:]))},
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported target %q", target)
	}
}
