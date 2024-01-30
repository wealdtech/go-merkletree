// Copyright © 2018 - 2023 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/wealdtech/go-merkletree/v2/blake2b"
)

// MultiProof is a single structure containing multiple proofs of a Merkle tree.
type MultiProof struct {
	// Values is the number of values in the Merkle tree.
	Values uint64
	// Hashes are indexed hashes of values that cannot be calculated from the index data
	Hashes map[uint64][]byte
	// Indices are the indices of the data that can be proved with the hashes
	Indices []uint64
	salt    bool
	// if sorted is true, the hash values are sorted before hashing branch nodes
	sorted bool
	hash   HashType
}

// NewMultiProof creates a new multiproof using the provided information.
func NewMultiProof(params ...Parameter) (*MultiProof, error) {
	parameters, err := parseAndCheckMultiProofParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	return &MultiProof{
		Values:  parameters.values,
		Hashes:  parameters.hashes,
		Indices: parameters.indices,
		salt:    parameters.salt,
		sorted:  parameters.sorted,
		hash:    parameters.hash,
	}, nil
}

// Verify verifies a multiproof.
func (p *MultiProof) Verify(data [][]byte, root []byte) (bool, error) {
	// Step 1 create hashes for all values.
	var proofHash []byte
	indexSalt := make([]byte, 4)
	for i, index := range p.Indices {
		if p.salt {
			binary.BigEndian.PutUint32(indexSalt, uint32(index))
			proofHash = p.hash.Hash(data[i], indexSalt)
		} else {
			proofHash = p.hash.Hash(data[i])
		}
		p.Hashes[index+p.Values] = proofHash
	}

	// Step 2 calculate values up the tree.
	for i := p.Values - 1; i > 0; i-- {
		_, exists := p.Hashes[i]
		if exists {
			continue
		}

		child1, exists := p.Hashes[i*2]
		if !exists {
			continue
		}

		child2, exists := p.Hashes[i*2+1]
		if !exists {
			continue
		}

		if p.sorted && bytes.Compare(child1, child2) == 1 {
			p.Hashes[i] = p.hash.Hash(child2, child1)
		} else {
			p.Hashes[i] = p.hash.Hash(child1, child2)
		}
	}

	return bytes.Equal(p.Hashes[1], root), nil
}

// VerifyMultiProof verifies multiple Merkle tree proofs for pieces of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
//
// Deprecated: please use MultiProof.Verify(...)
func VerifyMultiProof(data [][]byte, salt bool, proof *MultiProof, root []byte) (bool, error) {
	return VerifyMultiProofUsing(data, salt, proof, root, blake2b.New())
}

// VerifyMultiProofUsing verifies multiple Merkle tree proofs for pieces of data using the provided hash type.
// The proof and is as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
//
// Deprecated: please use MultiProof.Verify(...)
func VerifyMultiProofUsing(data [][]byte, salt bool, proof *MultiProof, root []byte, hashType HashType) (bool, error) {
	mp, err := NewMultiProof(
		WithSalt(salt),
		WithHashType(hashType),
		WithIndices(proof.Indices),
		WithHashes(proof.Hashes),
		WithValues(proof.Values),
	)
	if err != nil {
		return false, err
	}

	return mp.Verify(data, root)
}
