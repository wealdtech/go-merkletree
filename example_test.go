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
	"fmt"

	merkletree "github.com/wealdtech/go-merkletree/v2"
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

	fmt.Printf("%x\n", root)
	// Output: 2c95331b1a38dba3600391a3e864f9418a271388936e54edecd916824bb54203
}

// Example using a Merkle pollard rather than a simple root.
func ExampleMerklePollard() {
	// Data for the tree
	data := [][]byte{
		[]byte("Foo"),
		[]byte("Bar"),
		[]byte("Baz"),
		[]byte("Qux"),
		[]byte("Quux"),
		[]byte("Quuz"),
	}

	// Create the tree
	tree, err := merkletree.New(data)
	if err != nil {
		panic(err)
	}

	// Fetch the root and first level of branches as a pollard
	pollard := tree.Pollard(1)

	baz := data[2]
	// Generate a proof for 'Baz' up to (but not including) the first level of branches
	proof, err := tree.GenerateProof(baz, 1)
	if err != nil {
		panic(err)
	}

	// Verify the proof for 'Baz'
	verified, err := merkletree.VerifyProof(baz, false, proof, pollard)
	if err != nil {
		panic(err)
	}
	if !verified {
		panic("failed to verify proof for Baz")
	}

	fmt.Printf("%x\n", pollard)
	// Output: [9db41fa50e69f2d9ce73367bf8fd249fa960f6a416352f473693ea79540e516d 7799922ba259c0529cdfb9f974024d45abef9b3190850bc23fc5145cf81c9592 50824d0d95f73e4228e54705834c6fdaaa7fb22e1b8934a9100cc772f2d1d5f0]
}
