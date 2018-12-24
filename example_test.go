// Copyright © 2018 Weald Technology Trading
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

import merkletree "github.com/wealdtech/go-merkletree"

// testData is a structure that implements NodeData, allowing it to be stored in the Merkle tree.
type testData struct {
	data string
}

// Bytes provides a byte array that represents the testData.  This function implements the Merkle tree's NodeData interface.
func (t *testData) Bytes() []byte {
	return []byte(t.data)
}

// Example using the Merkle tree to generate and verify proofs.
func ExampleMerkleTree() {
	// Data for the tree
	data := []merkletree.NodeData{
		&testData{
			data: "Foo",
		},
		&testData{
			data: "Bar",
		},
		&testData{
			data: "Baz",
		},
	}

	// Create the tree
	tree, err := merkletree.New(data)
	if err != nil {
		panic(err)
	}

	// Fetch the root hash of the tree
	rootHash := tree.RootHash()

	baz := data[2]

	// Confirm that 'Baz' exists in the tree
	found := tree.ContainsData(baz)
	if !found {
		panic("failed to find Baz")
	}

	// Generate a proof for 'Baz'
	proof, path, err := tree.GenerateProof(baz)
	if err != nil {
		panic(err)
	}

	// Verify the proof for 'Baz'
	verified := merkletree.VerifyProof(baz, proof, path, rootHash)
	if !verified {
		panic("failed to verify proof for Baz")
	}
}
