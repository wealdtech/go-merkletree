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
	hashes [][]byte
	path   []bool
}

// newProof generates a Merkle proof
func newProof(hashes [][]byte, path []bool) *Proof {
	return &Proof{
		hashes: hashes,
		path:   path,
	}
}

// VerifyProof verifies a Merkle tree proof for a piece of data using the default hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProof(data NodeData, proof *Proof, root []byte) (bool, error) {
	return VerifyProofUsing(data, proof, root, blake2b.New())
}

func VerifyProofUsing(data NodeData, proof *Proof, root []byte, hashType HashType) (bool, error) {
	dataHash, err := hashType.Hash((data.Bytes()))
	if err != nil {
		return false, err
	}
	return VerifyProofFromHashUsing(dataHash, proof, root, hashType)
}

func VerifyProofFromHash(dataHash []byte, proof *Proof, root []byte) (bool, error) {
	return VerifyProofFromHashUsing(dataHash, proof, root, blake2b.New())
}

// VerifyProofFromHashUsing verifies a Merkle tree proof for a piece of data using the provided hash type.
// The proof and path are as per Merkle tree's GenerateProof(), and root is the root hash of the tree against which the proof is to
// be verified.  Note that this does not require the Merkle tree to verify the proof, only its root; this allows for checking
// against historical trees without having to instantiate them.
//
// This returns true if the proof is verified, otherwise false.
func VerifyProofFromHashUsing(dataHash []byte, proof *Proof, root []byte, hashType HashType) (bool, error) {
	var err error
	for i := range proof.hashes {
		if proof.path[i] {
			dataHash, err = hashType.Hash(append(proof.hashes[i], dataHash...))
			if err != nil {
				return false, err
			}
		} else {
			dataHash, err = hashType.Hash(append(dataHash, proof.hashes[i]...))
			if err != nil {
				return false, err
			}
		}
	}
	return bytes.Equal(dataHash, root), nil
}
