package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

type state struct {
	Target      string   `json:"target"`
	Size        int      `json:"size"`
	Input       []string `json:"input"`
	Constraints int      `json:"constraints"`
}

func writeJSON(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func readState(path string) (state, error) {
	var s state
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func writeArtifact(path string, value io.WriterTo) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = value.WriteTo(f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func readArtifact(path string, value io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = value.ReadFrom(f)
	return err
}

func prepare(path, target string, size int, input []string) error {
	shape, assignment, err := circuits(target, size, input)
	if err != nil {
		return err
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape)
	if err != nil {
		return err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	public, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	for suffix, artifact := range map[string]io.WriterTo{".r1cs": ccs, ".pk": pk, ".vk": vk, ".public": public} {
		if err := writeArtifact(path+suffix, artifact); err != nil {
			return err
		}
	}
	return writeJSON(path, state{target, size, input, ccs.GetNbConstraints()})
}

func prove(path string) error {
	s, err := readState(path)
	if err != nil {
		return err
	}
	_, assignment, err := circuits(s.Target, s.Size, s.Input)
	if err != nil {
		return err
	}
	ccs := groth16.NewCS(ecc.BN254)
	if err := readArtifact(path+".r1cs", ccs); err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readArtifact(path+".pk", pk); err != nil {
		return err
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		return err
	}
	return writeArtifact(path+".proof", proof)
}

// Verification consumes only the verification key, public witness and proof.
func verify(path string) error {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readArtifact(path+".vk", vk); err != nil {
		return err
	}
	public, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	if err := readArtifact(path+".public", public); err != nil {
		return err
	}
	proof := groth16.NewProof(ecc.BN254)
	if err := readArtifact(path+".proof", proof); err != nil {
		return err
	}
	return groth16.Verify(proof, vk, public)
}

func measure(path, sizesPath, constraintsPath string) error {
	if err := prove(path); err != nil {
		return err
	}
	s, err := readState(path)
	if err != nil {
		return err
	}
	var preprocessing int64
	for _, suffix := range []string{".r1cs", ".pk", ".vk"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			return err
		}
		preprocessing += info.Size()
	}
	proof, err := os.Stat(path + ".proof")
	if err != nil {
		return err
	}
	if err := writeJSON(sizesPath, map[string]int64{"proof_size": proof.Size(), "preprocessing_size": preprocessing}); err != nil {
		return err
	}
	counts := make(map[string]map[string]int)
	if b, err := os.ReadFile(constraintsPath); err == nil {
		if err := json.Unmarshal(b, &counts); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if counts[s.Target] == nil {
		counts[s.Target] = make(map[string]int)
	}
	counts[s.Target][strconv.Itoa(s.Size)] = s.Constraints
	return writeJSON(constraintsPath, counts)
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gnark-bench prepare <target> | prove | verify | measure <circuit_sizes.json>")
	}
	path := os.Getenv("STATE_JSON")
	if path == "" {
		return fmt.Errorf("STATE_JSON is required")
	}
	switch args[1] {
	case "prepare":
		if len(args) != 3 {
			return fmt.Errorf("prepare requires a target")
		}
		size, err := strconv.Atoi(os.Getenv("INPUT_SIZE"))
		if err != nil {
			return err
		}
		var lines []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return err
		}
		return prepare(path, args[2], size, lines)
	case "prove":
		return prove(path)
	case "verify":
		return verify(path)
	case "measure":
		if len(args) != 3 || os.Getenv("SIZES_JSON") == "" {
			return fmt.Errorf("measure requires a constraints path and SIZES_JSON")
		}
		return measure(path, os.Getenv("SIZES_JSON"), args[2])
	default:
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func main() {
	logger.Disable()
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
