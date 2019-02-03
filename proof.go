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

	"github.com/wealdtech/go-merkletree/blake2b"
)

// Proof is a proof of a Merkle tree
type Proof struct {
	Hashes [][]byte
	Index  uint64
}

// newProof generates a Merkle proof
func newProof(hashes [][]byte, index uint64) *Proof {
	return &Proof{
		Hashes: hashes,
		Index:  index,
	}
}

// VerifyProof verifies a Merkle tree proof for a piece of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProof(data []byte, proof *Proof, root []byte) (bool, error) {
	return VerifyProofUsing(data, proof, root, blake2b.New(), nil)
}

// VerifyProofUsing verifies a Merkle tree proof for a piece of data using the provided hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProofUsing(data []byte, proof *Proof, root []byte, hashType HashType, salt []byte) (bool, error) {
	var dataHash []byte
	if salt == nil {
		dataHash = hashType.Hash(data)
	} else {
		dataHash = hashType.Hash(append(data, salt...))
	}
	index := proof.Index + (1 << uint(len(proof.Hashes)))
	//	if index >= uint64(len(proof.Hashes)) {
	//		return false, errors.New("invalid proof")
	//	}

	for _, hash := range proof.Hashes {
		if index%2 == 0 {
			dataHash = hashType.Hash(append(dataHash, hash...))
		} else {
			dataHash = hashType.Hash(append(hash, dataHash...))
		}
		index = index >> 1
	}
	return bytes.Equal(dataHash, root), nil
}
