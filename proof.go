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

// VerifyProof verifies a Merkle tree proof for a piece of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProof(data NodeData, proof [][]byte, path []bool, root []byte) (bool, error) {
	return VerifyProofUsing(data, proof, path, root, blake2b.New())
}

// VerifyProofUsing verifies a Merkle tree proof for a piece of data using the provided hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProofUsing(data NodeData, proof [][]byte, path []bool, root []byte, hashType HashType) (bool, error) {
	hashFunc := hashType.Hash
	hash, err := hashFunc(data.Bytes())
	if err != nil {
		return false, err
	}
	for i := range proof {
		if path[i] {
			hash, err = hashFunc(append(proof[i], hash...))
			if err != nil {
				return false, err
			}
		} else {
			hash, err = hashFunc(append(hash, proof[i]...))
			if err != nil {
				return false, err
			}
		}
	}
	return bytes.Equal(hash, root), nil
}
