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

// Package merkletree is an implementation of a Merkle tree (https://en.wikipedia.org/wiki/Merkle_tree). It provides methods to
// create a tree and generate and verify proofs.  The hashing algorithm for the tree is selectable between BLAKE2b and Keccak256,
// or you can supply your own.
//
// This implementation includes advanced features salting and pollarding.  Salting is the act of adding a piece of data to each
// value in the Merkle tree as it is initially hashed to form the leaves, which helps avoid rainbow table attacks on leaf hashes
// presented as part of proofs.  Pollarding is the act of providing the root plus all branches to a certain height which can be
// used to reduce the size of proofs.  This is useful when multiple proofs are presented against the same tree as it can reduce the
// overall size.
//
// Creating a Merkle tree requires a list of values that are each byte arrays.  Once a tree has been created proofs can be generated
// using the tree's GenerateProof() function.
//
// The package includes a function VerifyProof() to verify a generated proof given only the data to prove, proof and the pollard of
// the relevant Merkle tree.  This allows for efficient verification of proofs without requiring the entire Merkle tree to be stored
// or recreated.
//
//
// Implementation notes
//
//
// The tree pads its values to the next highest power of 2; values not supplied are treated as null with a value hash of 0.  This can
// be seen graphically by generating a DOT representation of the graph with DOT().
//
// If salting is enabled it appends an 4-byte value to each piece of data.  The value is the binary representation of the index in
// big-endian form.  Note that if there are more than 2^32 values in the tree the salt will wrap, being modulo 2^32
package merkletree

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/wealdtech/go-merkletree/blake2b"
)

// MerkleTree is the structure for the Merkle tree.
type MerkleTree struct {
	// if salt is true the data values are salted with their index
	salt bool
	// hash is a pointer to the hashing struct
	hash HashType
	// data is the data from which the Merkle tree is created
	data [][]byte
	// nodes are the leaf and branch nodes of the Merkle tree
	nodes [][]byte
}

func (t *MerkleTree) indexOf(input []byte) (uint64, error) {
	for i, data := range t.data {
		if bytes.Compare(data, input) == 0 {
			return uint64(i), nil
		}
	}
	return 0, errors.New("data not found")
}

// GenerateProof generates the proof for a piece of data.
// Height is the height of the pollard to verify the proof.  If using the Merkle root to verify this should be 0.
// If the data is not present in the tree this will return an error.
// If the data is present in the tree this will return the hashes for each level in the tree and the index of the value in the tree
func (t *MerkleTree) GenerateProof(data []byte, height int) (*Proof, error) {
	// Find the index of the data
	index, err := t.indexOf(data)
	if err != nil {
		return nil, err
	}

	proofLen := int(math.Ceil(math.Log2(float64(len(t.data))))) - height
	hashes := make([][]byte, proofLen)

	cur := 0
	minI := uint64(math.Pow(2, float64(height+1))) - 1
	for i := index + uint64(len(t.nodes)/2); i > minI; i /= 2 {
		hashes[cur] = t.nodes[i^1]
		cur++
	}
	return newProof(hashes, index), nil
}

// New creates a new Merkle tree using the provided raw data and default hash type.  Salting is not used.
// data must contain at least one element for it to be valid.
func New(data [][]byte) (*MerkleTree, error) {
	return NewUsing(data, blake2b.New(), false)
}

// NewUsing creates a new Merkle tree using the provided raw data and supplied hash type.  Salting is used if requested.
// data must contain at least one element for it to be valid.
func NewUsing(data [][]byte, hash HashType, salt bool) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	branchesLen := int(math.Exp2(math.Ceil(math.Log2(float64(len(data))))))

	// We pad our data length up to the power of 2
	nodes := make([][]byte, branchesLen+len(data)+(branchesLen-len(data)))
	// Leaves
	indexSalt := make([]byte, 4)
	for i := range data {
		if salt {
			binary.BigEndian.PutUint32(indexSalt, uint32(i))
			nodes[i+branchesLen] = hash.Hash(data[i], indexSalt[:])
		} else {
			nodes[i+branchesLen] = hash.Hash(data[i])
		}
	}
	for i := len(data) + branchesLen; i < len(nodes); i++ {
		nodes[i] = make([]byte, hash.HashLength())
	}
	// Branches
	for i := branchesLen - 1; i > 0; i-- {
		nodes[i] = hash.Hash(nodes[i*2], nodes[i*2+1])
	}

	tree := &MerkleTree{
		salt:  salt,
		hash:  hash,
		nodes: nodes,
		data:  data,
	}

	return tree, nil
}

// Pollard returns the Merkle root plus branches to a certain height.  Height 0 will return just the root, height 1 the root plus
// the two branches directly above it, height 2 the root, two branches directly above it and four branches directly above them, etc.
func (t *MerkleTree) Pollard(height int) [][]byte {
	return t.nodes[1:int(math.Exp2(float64(height+1)))]
}

// Root returns the Merkle root (hash of the root node) of the tree.
func (t *MerkleTree) Root() []byte {
	return t.nodes[1]
}

// Salt returns the true if the values in this Merkle tree are salted.
func (t *MerkleTree) Salt() bool {
	return t.salt
}

// String implements the stringer interface
func (t *MerkleTree) String() string {
	return fmt.Sprintf("%x", t.nodes[1])
}
