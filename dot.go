// Copyright © 2018 - 2023 Weald Technology Trading
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
		index := proof.Index + uint64(math.Ceil(float64(len(t.Nodes))/2))
		valueIndices[proof.Index] = 1

		for range proof.Hashes {
			proofIndices[index^1] = 1
			index /= 2
		}

		numRootNodes := uint64(math.Exp2(math.Ceil(math.Log2(float64(len(t.Data))))-float64(len(proof.Hashes))+1)) - 1
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
	dataLen := len(t.Data)
	valuesOffset := int(math.Ceil(float64(len(t.Nodes)) / 2))
	var nodeBuilder strings.Builder
	nodeBuilder.WriteString("{rank=same")
	for i := 0; i < valuesOffset; i++ {
		if i < dataLen {
			t.dotLeaf(&builder, &nodeBuilder, i, valuesOffset+i, lf, bf, valueIndices, rootIndices, proofIndices)
		} else {
			t.dotEmptyLeaf(&builder, &nodeBuilder, valuesOffset+i, bf, rootIndices, proofIndices)
		}
		if dataLen > 1 {
			builder.WriteString(fmt.Sprintf("%d->%d;", valuesOffset+i, (valuesOffset+i)/2))
		}
	}
	nodeBuilder.WriteString("};")
	builder.WriteString(nodeBuilder.String())

	// Add branches
	for valueIndex := valuesOffset - 1; valueIndex > 0; valueIndex-- {
		builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", valueIndex, bf.Format(t.Nodes[valueIndex])))
		if rootIndices[uint64(valueIndex)] > 0 {
			builder.WriteString(" style=filled fillcolor=\"#8080ff\"")
		} else if proofIndices[uint64(valueIndex)] > 0 {
			builder.WriteString(" style=filled fillcolor=\"#00ff00\"")
		}
		builder.WriteString("];")
		if valueIndex > 1 {
			builder.WriteString(fmt.Sprintf("%d->%d;", valueIndex, valueIndex/2))
		}
	}
	builder.WriteString("}")

	return builder.String()
}

func (t *MerkleTree) dotLeaf(builder *strings.Builder,
	nodeBuilder *strings.Builder,
	i int,
	offset int,
	leafFormatter Formatter,
	branchFormatter Formatter,
	valueIndices map[uint64]int,
	rootIndices map[uint64]int,
	proofIndices map[uint64]int,
) {
	builder.WriteString(fmt.Sprintf("\"%s\" [shape=oval", leafFormatter.Format(t.Data[i])))
	if valueIndices[uint64(i)] > 0 {
		builder.WriteString(" style=filled fillcolor=\"#ff4040\"")
	}
	builder.WriteString("];")

	// Hash of the value
	if t.Salt {
		indexSalt := make([]byte, 4)
		binary.BigEndian.PutUint32(indexSalt, uint32(i))
		builder.WriteString(fmt.Sprintf("\"%s\"->%d [label=\"+%0x\"];", leafFormatter.Format(t.Data[i]), offset, indexSalt))
	} else {
		builder.WriteString(fmt.Sprintf("\"%s\"->%d;", leafFormatter.Format(t.Data[i]), offset))
	}

	nodeBuilder.WriteString(fmt.Sprintf(";%d", offset))
	builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", offset, branchFormatter.Format(t.Nodes[offset])))
	if proofIndices[uint64(offset)] > 0 {
		builder.WriteString(" style=filled fillcolor=\"#00ff00\"")
	} else if rootIndices[uint64(offset)] > 0 {
		builder.WriteString(" style=filled fillcolor=\"#8080ff\"")
	}
	builder.WriteString("];")
	if i > 0 {
		builder.WriteString(fmt.Sprintf("%d->%d [style=invisible arrowhead=none];", offset-1, offset))
	}
}

func (t *MerkleTree) dotEmptyLeaf(builder *strings.Builder,
	nodeBuilder *strings.Builder,
	offset int,
	branchFormatter Formatter,
	rootIndices map[uint64]int,
	proofIndices map[uint64]int,
) {
	empty := make([]byte, len(t.Nodes[1]))

	builder.WriteString(fmt.Sprintf("%d [label=\"%s\"", offset, branchFormatter.Format(empty)))
	if proofIndices[uint64(offset)] > 0 {
		builder.WriteString(" style=filled fillcolor=\"#00ff00\"")
	} else if rootIndices[uint64(offset)] > 0 {
		builder.WriteString(" style=filled fillcolor=\"#8080ff\"")
	}
	builder.WriteString("];")
	builder.WriteString(fmt.Sprintf("%d->%d [style=invisible arrowhead=none];", offset-1, offset))
	nodeBuilder.WriteString(fmt.Sprintf(";%d", offset))
}
