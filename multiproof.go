// Copyright © 2018, 2019 Weald Technology Trading
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

	"github.com/wealdtech/go-merkletree/blake2b"
)

// MultiProof is a single structure containing multiple proofs of a Merkle tree.
type MultiProof struct {
	// Values is the number of values in the Merkle tree
	Values uint64
	// Hashes are indexed hashes of values that cannot be calculated from the index data
	Hashes map[uint64][]byte
	// Indices are the indices of the data that can be proved with the hashes
	Indices []uint64
}

// newMultiProof generates a Merkle proof
func newMultiProof(hashes map[uint64][]byte, indices []uint64, values uint64) *MultiProof {
	return &MultiProof{
		Values:  values,
		Hashes:  hashes,
		Indices: indices,
	}
}

// VerifyMultiProof verifies multiple Merkle tree proofs for pieces of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyMultiProof(data [][]byte, salt bool, proof *MultiProof, root []byte) (bool, error) {
	return VerifyMultiProofUsing(data, salt, proof, root, blake2b.New())
}

// VerifyMultiProofUsing verifies multiple Merkle tree proofs for pieces of data using the provided hash type.
// The proof and is as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyMultiProofUsing(data [][]byte, salt bool, proof *MultiProof, root []byte, hashType HashType) (bool, error) {
	// Step 1 create hashes for all values
	var proofHash []byte
	indexSalt := make([]byte, 4)
	for i, index := range proof.Indices {
		if salt {
			binary.BigEndian.PutUint32(indexSalt, uint32(index))
			proofHash = hashType.Hash(data[i], indexSalt)
		} else {
			proofHash = hashType.Hash(data[i])
		}
		proof.Hashes[index+proof.Values] = proofHash
	}

	// Step 2 calculate values up the tree
	for i := proof.Values - 1; i > 0; i-- {
		_, exists := proof.Hashes[i]
		if !exists {
			child1, exists := proof.Hashes[i*2]
			if exists {
				child2, exists := proof.Hashes[i*2+1]
				if exists {
					proof.Hashes[i] = hashType.Hash(child1, child2)
				}
			}
		}
	}

	if !bytes.Equal(proof.Hashes[1], root) {
		return false, nil
	}
	return true, nil
}
