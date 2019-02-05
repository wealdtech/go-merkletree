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

package merkletree_test

import (
	merkletree "github.com/wealdtech/go-merkletree"
)

// Example using the Merkle tree to generate and verify proofs.
func ExampleMerkleTree() {
	// Data for the tree
	data := [][]byte{
		[]byte("Foo"),
		[]byte("Bar"),
		[]byte("Baz"),
	}

	// Create the tree
	tree, err := merkletree.New(data)
	if err != nil {
		panic(err)
	}

	// Fetch the root hash of the tree
	root := tree.Root()

	baz := data[2]
	// Generate a proof for 'Baz'
	proof, err := tree.GenerateProof(baz, 0)
	if err != nil {
		panic(err)
	}

	// Verify the proof for 'Baz'
	verified, err := merkletree.VerifyProof(baz, false, proof, [][]byte{root})
	if err != nil {
		panic(err)
	}
	if !verified {
		panic("failed to verify proof for Baz")
	}
}
