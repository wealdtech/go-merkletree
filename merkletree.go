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
// # Implementation notes
//
// The tree pads its values to the next highest power of 2; values not supplied are treated as null with a value hash of 0.  This
// can be seen graphically by generating a DOT representation of the graph with DOT().
//
// If salting is enabled it appends an 4-byte value to each piece of data.  The value is the binary representation of the index in
// big-endian form.  Note that if there are more than 2^32 values in the tree the salt will wrap, being modulo 2^32
package merkletree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"

	"github.com/pkg/errors"
)

// MerkleTree is the structure for the Merkle tree.
type MerkleTree struct {
	// if Salt is true the Data values are salted with their index
	Salt bool `json:"salt"`
	// if Sorted is true, the Hash values are Sorted before hashing branch Nodes
	Sorted bool `json:"sorted"`
	// Hash is a pointer to the hashing struct
	Hash HashType `json:"hash_type"`
	// Data is the Data from which the Merkle tree is created
	Data [][]byte `json:"data"`
	// Nodes are the leaf and branch Nodes of the Merkle tree
	Nodes [][]byte `json:"nodes"`
}

// A container which gives us the ability to sort the hashes by value
// while maintaining the relative positions of the data and it's hash.
type hashSorter struct {
	// data from which the hashes are generated
	data [][]byte
	// Hashes of the data
	hashes [][]byte
}

// Len length of the data slice.
func (s hashSorter) Len() int {
	return len(s.data)
}

// Swap the given indicies in both the data and leaf slices.
func (s hashSorter) Swap(i, j int) {
	s.data[i], s.data[j] = s.data[j], s.data[i]
	s.hashes[i], s.hashes[j] = s.hashes[j], s.hashes[i]
}

// Compares the hash indicies, returns true if i is less than j.
func (s hashSorter) Less(i, j int) bool {
	return bytes.Compare(s.hashes[i], s.hashes[j]) == -1
}

// Index of the data in the MerkleTree.
func (t *MerkleTree) indexOf(input []byte) (uint64, error) {
	for i, data := range t.Data {
		if bytes.Equal(data, input) {
			return uint64(i), nil
		}
	}

	return 0, errors.New("data not found")
}

// GenerateProof generates the proof for a piece of data.
// Height is the height of the pollard to verify the proof.  If using the Merkle root to verify this should be 0.
// If the data is not present in the tree this will return an error.
// If the data is present in the tree this will return the hashes for each level in the tree and the index of the value in the tree.
func (t *MerkleTree) GenerateProof(data []byte, height int) (*Proof, error) {
	// Find the index of the data
	index, err := t.indexOf(data)
	if err != nil {
		return nil, err
	}

	proofLen := int(math.Ceil(math.Log2(float64(len(t.Data))))) - height
	hashes := make([][]byte, proofLen)

	cur := 0
	minI := uint64(math.Pow(2, float64(height+1))) - 1
	for i := index + uint64(len(t.Nodes)/2); i > minI; i /= 2 {
		hashes[cur] = t.Nodes[i^1]
		cur++
	}

	return newProof(hashes, index), nil
}

// GenerateMultiProof generates the proof for multiple pieces of data.
func (t *MerkleTree) GenerateMultiProof(data [][]byte) (*MultiProof, error) {
	hashes := make([][][]byte, len(data))
	indices := make([]uint64, len(data))

	// Step 1: generate individual proofs.
	for dataIndex := range data {
		tmpProof, err := t.GenerateProof(data[dataIndex], 0)
		if err != nil {
			return nil, err
		}
		hashes[dataIndex] = tmpProof.Hashes
		indices[dataIndex] = tmpProof.Index
	}

	// Step 2: combine the hashes across all proofs and highlight all calculated indices.
	proofHashes := make(map[uint64][]byte)
	calculatedIndices := make([]bool, len(t.Nodes))
	for i, index := range indices {
		hashNum := 0
		for j := index + uint64(math.Ceil(float64(len(t.Nodes))/2)); j > 1; j /= 2 {
			proofHashes[j^1] = hashes[i][hashNum]
			calculatedIndices[j] = true
			hashNum++
		}
	}

	// Step 3: remove any hashes that can be calculated.
	for _, index := range indices {
		for j := index + uint64(math.Ceil(float64(len(t.Nodes))/2)); j > 1; j /= 2 {
			if calculatedIndices[j^1] {
				delete(proofHashes, j^1)
			}
		}
	}

	return NewMultiProof(
		WithHashes(proofHashes),
		WithSalt(t.Salt),
		WithSorted(t.Sorted),
		WithHashType(t.Hash),
		WithIndices(indices),
		WithValues(uint64(len(t.Nodes)/2)),
	)
}

// NewTree creates a new merkle tree using the provided information.
func NewTree(params ...Parameter) (*MerkleTree, error) {
	parameters, err := parseAndCheckTreeParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	branchesLen := int(math.Exp2(math.Ceil(math.Log2(float64(len(parameters.data))))))

	// We pad our data length up to the power of 2.
	nodes := make([][]byte, branchesLen+len(parameters.data)+(branchesLen-len(parameters.data)))

	// We put the leaves after the branches in the slice of nodes.
	createLeaves(
		parameters.data,
		nodes[branchesLen:branchesLen+len(parameters.data)],
		parameters.hash,
		parameters.salt,
		parameters.sorted,
	)
	// Pad the space left after the leaves.
	for i := len(parameters.data) + branchesLen; i < len(nodes); i++ {
		nodes[i] = make([]byte, parameters.hash.HashLength())
	}

	// Branches.
	createBranches(
		nodes,
		parameters.hash,
		branchesLen,
		parameters.sorted,
	)

	tree := &MerkleTree{
		Salt:   parameters.salt,
		Sorted: parameters.sorted,
		Hash:   parameters.hash,
		Nodes:  nodes,
		Data:   parameters.data,
	}

	return tree, nil
}

// New creates a new Merkle tree using the provided raw data and default hash type.  Salting is not used.
// data must contain at least one element for it to be valid.
// Deprecated: plase use NewTree().
func New(data [][]byte) (*MerkleTree, error) {
	return NewTree(WithData(data))
}

// Hashes the data slice, placing the result hashes into dest.
// salt adds a salt to the hash using the index.
// sorted sorts the leaves and data by the value of the leaf hash.
func createLeaves(data [][]byte, dest [][]byte, hash HashType, salt, sorted bool) {
	indexSalt := make([]byte, 4)
	for i := range data {
		if salt {
			binary.BigEndian.PutUint32(indexSalt, uint32(i))
			dest[i] = hash.Hash(data[i], indexSalt)
		} else {
			dest[i] = hash.Hash(data[i])
		}
	}

	if sorted {
		sorter := hashSorter{
			data:   data,
			hashes: dest,
		}
		sort.Sort(sorter)
	}
}

// Create the branch nodes from the existing leaf data.
func createBranches(nodes [][]byte, hash HashType, leafOffset int, sorted bool) {
	for leafIndex := leafOffset - 1; leafIndex > 0; leafIndex-- {
		left := nodes[leafIndex*2]
		right := nodes[leafIndex*2+1]

		if sorted && bytes.Compare(left, right) == 1 {
			nodes[leafIndex] = hash.Hash(right, left)
		} else {
			nodes[leafIndex] = hash.Hash(left, right)
		}
	}
}

// NewUsing creates a new Merkle tree using the provided raw data and supplied hash type.
// Salting is used, and hashes are sorted if requested.
// data must contain at least one element for it to be valid.
// Deprecated: plase use NewTree().
func NewUsing(data [][]byte, hash HashType, salt bool) (*MerkleTree, error) {
	return NewTree(
		WithData(data),
		WithHashType(hash),
		WithSalt(salt),
	)
}

// Pollard returns the Merkle root plus branches to a certain height.  Height 0 will return just the root, height 1 the root plus
// the two branches directly above it, height 2 the root, two branches directly above it and four branches directly above them, etc.
func (t *MerkleTree) Pollard(height int) [][]byte {
	return t.Nodes[1:int(math.Exp2(float64(height+1)))]
}

// Root returns the Merkle root (hash of the root node) of the tree.
func (t *MerkleTree) Root() []byte {
	return t.Nodes[1]
}

// GetSalt returns the true if the values in this Merkle tree are salted.
func (t *MerkleTree) GetSalt() bool {
	return t.Salt
}

// String implements the stringer interface.
func (t *MerkleTree) String() string {
	return hex.EncodeToString(t.Nodes[1])
}
