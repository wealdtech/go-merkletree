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
// Creating a Merkle tree requires a list of values that are each byte arrays.  Once a tree has been created proofs can be generated
// using the tree's GenerateProof() function.
//
// The package includes a function to verify a generated proof given only the data to prove, proof and the root hash of the relevant
// Merkle tree.  This allows for efficient verification of proofs without requiring the entire Merkle tree to be stored or recreated.
//
// Implementation notes
//
// The tree pads its values to the next highest power of 2; values not supplied are treated as 0.  This can be seen graphically by
// generating a DOT representation of the graph with DOT().
package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/wealdtech/go-merkletree/blake2b"
)

// MerkleTree is the top-level structure for the merkle tree.
type MerkleTree struct {
	// salt is the optional salt hashed with data to avoid rainbow attacks
	salt []byte
	// hash is a pointer to the hashing struct
	hash HashFunc
	// data is the data from which the Merkle tree is created
	data [][]byte
	// nodes are the leaf and branch nodes of the Merkle tree
	nodes [][]byte
}

// DOT creates a DOT representation of the tree.  It is generally used for external presentation.
// This takes two optional formatters for []byte data: the first for leaf data and the second for branches.
func (t *MerkleTree) DOT(lf Formatter, bf Formatter) string {
	if lf == nil {
		lf = new(TruncatedHexFormatter)
	}
	if bf == nil {
		bf = new(TruncatedHexFormatter)
	}

	var builder strings.Builder
	builder.WriteString("digraph MerkleTree {")
	builder.WriteString("rankdir = BT;")
	builder.WriteString("node [shape=rectangle margin=\"0.2,0.2\"];")
	empty := make([]byte, len(t.nodes[1]))
	dataLen := len(t.data)
	valuesOffset := len(t.nodes) / 2
	var nodeBuilder strings.Builder
	nodeBuilder.WriteString("{rank=same")
	for i := 0; i < valuesOffset; i++ {
		if i < dataLen {
			// Real data
			builder.WriteString(fmt.Sprintf("\"%s\" [shape=oval];", lf.Format(t.data[i])))
			builder.WriteString(fmt.Sprintf("\"%s\"->%d;", lf.Format(t.data[i]), valuesOffset+i))
			nodeBuilder.WriteString(fmt.Sprintf(";%d", valuesOffset+i))
			builder.WriteString(fmt.Sprintf("%d [label=\"%s\"];", valuesOffset+i, bf.Format(t.nodes[valuesOffset+i])))
			if i > 0 {
				builder.WriteString(fmt.Sprintf("%d->%d [style=invisible arrowhead=none];", valuesOffset+i-1, valuesOffset+i))
			}
		} else {
			// Empty leaf
			builder.WriteString(fmt.Sprintf("%d [label=\"%s\"];", valuesOffset+i, bf.Format(empty)))
			builder.WriteString(fmt.Sprintf("%d->%d [style=invisible arrowhead=none];", valuesOffset+i-1, valuesOffset+i))
			nodeBuilder.WriteString(fmt.Sprintf(";%d", valuesOffset+i))
		}
		if dataLen > 1 {
			builder.WriteString(fmt.Sprintf("%d->%d;", valuesOffset+i, (valuesOffset+i)/2))
		}
	}
	nodeBuilder.WriteString("};")
	builder.WriteString(nodeBuilder.String())

	// Add branches
	for i := valuesOffset - 1; i > 0; i-- {
		builder.WriteString(fmt.Sprintf("%d [label=\"%s\"];", i, bf.Format(t.nodes[i])))
		if i > 1 {
			builder.WriteString(fmt.Sprintf("%d->%d;", i, i/2))
		}
	}
	builder.WriteString("}")
	return builder.String()
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
// If the data is not present in the tree this will return an error.
// If the data is present in the tree this will return the hashes for each level in the tree and details of if the hashes returned
// are the left-hand or right-hand hashes at each level (true if the left-hand, false if the right-hand).
func (t *MerkleTree) GenerateProof(data []byte) (*Proof, error) {
	// Find the index of the data
	index, err := t.indexOf(data)
	if err != nil {
		return nil, err
	}

	proofLen := int(math.Ceil(math.Log2(float64(len(t.data)))))
	hashes := make([][]byte, proofLen)

	cur := 0
	for i := index + uint64(len(t.nodes)/2); i > 1; i /= 2 {
		hashes[cur] = t.nodes[i^1]
		cur++
	}
	return newProof(hashes, index), nil
}

// New creates a new Merkle tree using the provided raw data and default hash type.
// data must contain at least one element for it to be valid.
func New(data [][]byte) (*MerkleTree, error) {
	return NewUsing(data, blake2b.New(), nil)
}

// NewUsing creates a new Merkle tree using the provided raw data and supplied hash type.
// data must contain at least one element for it to be valid.
func NewUsing(data [][]byte, hash HashType, salt []byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	branchesLen := int(math.Exp2(math.Ceil(math.Log2(float64(len(data))))))

	// We pad our data length up to the power of 2
	nodes := make([][]byte, branchesLen+len(data)+(branchesLen-len(data)))
	// Leaves
	for i := range data {
		if salt == nil {
			nodes[i+branchesLen] = hash.Hash(data[i])
		} else {
			nodes[i+branchesLen] = hash.Hash(append(data[i], salt...))
		}
	}
	// Branches
	for i := branchesLen - 1; i > 0; i-- {
		nodes[i] = hash.Hash(append(nodes[i*2], nodes[i*2+1]...))
	}

	tree := &MerkleTree{
		salt:  salt,
		hash:  hash.Hash,
		nodes: nodes,
		data:  data,
	}

	return tree, nil
}

// Root returns the Merkle root (hash of the root node) of the tree.
func (t *MerkleTree) Root() []byte {
	return t.nodes[1]
}

// String implements the stringer interface
func (t *MerkleTree) String() string {
	return fmt.Sprintf("%x", t.nodes[1])
}
