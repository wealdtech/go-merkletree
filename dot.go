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
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// DOT creates a DOT representation of the tree.  It is generally used for external presentation.
// This takes two optional formatters for []byte data: the first for leaf data and the second for branches.
func (t *MerkleTree) DOT(lf Formatter, bf Formatter) string {
	return t.dot(nil, nil, nil, lf, bf)
}

// DOTProof creates a DOT representation of the tree with highlights for a proof.  It is generally used for external presentation.
// This takes two optional formatters for []byte data: the first for leaf data and the second for branches.
func (t *MerkleTree) DOTProof(proof *Proof, lf Formatter, bf Formatter) string {
	if proof == nil {
		return t.DOT(lf, bf)
	}

	// Find out which nodes are used in our proof
	valueIndices := make(map[uint64]int)
	proofIndices := make(map[uint64]int)
	rootIndices := make(map[uint64]int)

	if proof != nil {
		index := proof.Index + uint64(math.Ceil(float64(len(t.nodes))/2))
		valueIndices[proof.Index] = 1

		for _ = range proof.Hashes {
			proofIndices[index^1] = 1
			index /= 2
		}

		numRootNodes := uint64(math.Exp2(math.Ceil(math.Log2(float64(len(t.data))))-float64(len(proof.Hashes))+1)) - 1
		for i := uint64(1); i <= numRootNodes; i++ {
			rootIndices[i] = 1
		}
	}

	return t.dot(rootIndices, valueIndices, proofIndices, lf, bf)
}

// DOTMultiProof creates a DOT representation of the tree with highlights for a multiproof.  It is generally used for external
// presentation.  This takes two optional formatters for []byte data: the first for leaf data and the second for branches.
func (t *MerkleTree) DOTMultiProof(multiProof *MultiProof, lf Formatter, bf Formatter) string {
	if multiProof == nil {
		return t.DOT(lf, bf)
	}

	// Find out which nodes are used in our multiproof
	valueIndices := make(map[uint64]int)
	proofIndices := make(map[uint64]int)
	rootIndices := make(map[uint64]int)

	for _, index := range multiProof.Indices {
		valueIndices[index] = 1
	}
	for index := range multiProof.Hashes {
		proofIndices[index] = 1
	}
	rootIndices[1] = 1
	return t.dot(rootIndices, valueIndices, proofIndices, lf, bf)
}

func (t *MerkleTree) dot(rootIndices, valueIndices, proofIndices map[uint64]int, lf, bf Formatter) string {
	if lf == nil {
		lf = new(TruncatedHexFormatter)
	}
	if bf == nil {
		bf = new(TruncatedHexFormatter)
	}

	var builder strings.Builder
	builder.WriteString("digraph MerkleTree {")
	builder.WriteString("rankdir = TB;")
	builder.WriteString("node [shape=rectangle margin=\"0.2,0.2\"];")
	empty := make([]byte, len(t.nodes[1]))
	dataLen := len(t.data)
	valuesOffset := int(math.Ceil(float64(len(t.nodes)) / 2))
	var nodeBuilder strings.Builder
	nodeBuilder.WriteString("{rank=same")
	indexSalt := make([]byte, 4)
	for i := 0; i < valuesOffset; i++ {
		if i < dataLen {
			// Value
			builder.WriteString(fmt.Sprintf("\"%s\" [shape=oval", lf.Format(t.data[i])))
			if valueIndices[uint64(i)] > 0 {
				builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#ff4040\""))
			}
			builder.WriteString("];")

			// Hash of the value
			if t.salt {
				binary.BigEndian.PutUint32(indexSalt, uint32(i))
				builder.WriteString(fmt.Sprintf("\"%s\"->%d [label=\"+%0x\"];", lf.Format(t.data[i]), valuesOffset+i, indexSalt))
			} else {
				builder.WriteString(fmt.Sprintf("\"%s\"->%d;", lf.Format(t.data[i]), valuesOffset+i))
			}

			nodeBuilder.WriteString(fmt.Sprintf(";%d", valuesOffset+i))
			builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", valuesOffset+i, bf.Format(t.nodes[valuesOffset+i])))
			if proofIndices[uint64(i+valuesOffset)] > 0 {
				builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#00ff00\""))
			} else if rootIndices[uint64(i+valuesOffset)] > 0 {
				builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#8080ff\""))
			}
			builder.WriteString("];")
			if i > 0 {
				builder.WriteString(fmt.Sprintf("%d->%d [style=invisible arrowhead=none];", valuesOffset+i-1, valuesOffset+i))
			}
		} else {
			// Empty leaf
			builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", valuesOffset+i, bf.Format(empty)))
			if proofIndices[uint64(i+valuesOffset)] > 0 {
				builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#00ff00\""))
			} else if rootIndices[uint64(i+valuesOffset)] > 0 {
				builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#8080ff\""))
			}
			builder.WriteString("];")
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
		builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", i, bf.Format(t.nodes[i])))
		if rootIndices[uint64(i)] > 0 {
			builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#8080ff\""))
		} else if proofIndices[uint64(i)] > 0 {
			builder.WriteString(fmt.Sprintf(" style=filled fillcolor=\"#00ff00\""))
		}
		builder.WriteString("];")
		if i > 1 {
			builder.WriteString(fmt.Sprintf("%d->%d;", i, i/2))
		}
	}
	builder.WriteString("}")
	return builder.String()
}
