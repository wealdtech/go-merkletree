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

// Package merkletree is an implementation of a Merkle tree (https://en.wikipedia.org/wiki/Merkle_tree). It provides methods to
// create a tree and generate and verify proofs.
//
// Creating a Merkle tree requires a list of objects that implement the NodeData interface.  Once a tree has been created proofs
// can be generated using the tree's GenerateProof() function.
//
// The package includes a function to verify a generated proof given only the data, proof and the root hash of the relevant Merkle
// tree.  This allows for efficient verification of proofs without requiring the entire Merkle tree to be stored or recreated.
//
// Implementation notes
//
// This package uses the BLAKE2b hashing algorithm (https://godoc.org/golang.org/x/crypto/blake2b) to generate node hashes.
//
// If there is an odd number of nodes at any level in the tree (except the root) the last node is used as both left and right nodes
// when generating the hash for the parent node.
package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// MerkleTree is the top-level structure for the merkle tree.
type MerkleTree struct {
	root *Node
}

// ContainsData returns true if the tree contains the provided data, otherwise false.
func (t *MerkleTree) ContainsData(data NodeData) bool {
	return t.findLeafNode(data) != nil
}

// DOT creates a DOT representation of the tree.  It is generally used for external presentation.
func (t *MerkleTree) DOT() string {
	var builder strings.Builder
	builder.WriteString("digraph MerkleTree {")
	builder.WriteString("node [shape=rectangle margin=\"0.2,0.2\"];")
	dotNode(t.root, &builder)
	builder.WriteString("}")
	return builder.String()
}

// GenerateProof generates the proof for a piece of data.
// If the data is not present in the tree this will return an error.
// If the data is present in the tree this will return the hashes for each level in the tree and details of if the hashes returned
// are the left-hand or right-hand hashes at each level (true if the left-hand, false if the right-hand).
func (t *MerkleTree) GenerateProof(data NodeData) ([][]byte, []bool, error) {
	// Find the leaf node in the tree that contains the data
	node := t.findLeafNode(data)
	if node == nil {
		return nil, nil, errors.New("merkle tree does not contain this data")
	}

	// Build the proof and associated path
	proof := make([][]byte, 0)
	path := make([]bool, 0)
	for {
		if node.IsRoot() {
			return proof, path, nil
		}
		if node.parent.left == node {
			proof = append(proof, node.parent.right.hash)
			path = append(path, false)
		} else {
			proof = append(proof, node.parent.left.hash)
			path = append(path, true)
		}
		node = node.parent
	}
}

// New creates a new Merkle tree using the provided data.
// nodeData must contain at least one element for it to be valid.
func New(nodeData []NodeData) (*MerkleTree, error) {
	if len(nodeData) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}
	// Step 1: turn the node data in to leaf nodes
	var nodes []*Node
	for _, data := range nodeData {
		nodes = append(nodes, &Node{
			hash: hashBytes(data.Bytes()),
			data: data,
		})
	}

	// Step 2: iterate up the tree until only one node is left
	for {
		nodes = buildParents(nodes)
		if len(nodes) == 1 {
			break
		}
	}
	return &MerkleTree{
		root: nodes[0],
	}, nil
}

// Replace replaces an existing node with new data, regenerating the tree hashes as required to remain accurate.
func (t *MerkleTree) Replace(old NodeData, new NodeData) error {
	// Find the node for the data
	node := t.findLeafNode(old)
	if node == nil {
		return errors.New("merkle tree does not contain this data")
	}

	// Replace the node's data
	node.data = new

	// Regenerate the hashes from this node
	t.regenerateHashes(node)

	return nil
}

// RootHash returns the Merkle root (hash of the root node) of the tree.
func (t *MerkleTree) RootHash() []byte {
	return t.root.hash
}

// String implements the stringer interface
func (t *MerkleTree) String() string {
	return fmt.Sprintf("%x", t.root.hash)
}

// buildParents builds the parent nodes for a list of nodes.  The nodes passed in can be leaves or intermediate nodes.
// This is used by New() to construct the non-leaf nodes.
func buildParents(nodes []*Node) []*Node {
	parentNodes := make([]*Node, 0)
	for i := 0; i < len(nodes); i += 2 {
		left := i
		right := i + 1
		if right == len(nodes) {
			// We have an odd nuber of nodes; use a copy of the left-hand node as the right-hand node to make it even
			right = left
		}
		parentNode := &Node{
			left:  nodes[left],
			right: nodes[right],
			hash:  hashBytes(append(nodes[left].hash, nodes[right].hash...)),
		}
		nodes[left].parent = parentNode
		nodes[right].parent = parentNode
		parentNodes = append(parentNodes, parentNode)
	}
	return parentNodes
}

// dotNode creates a DOT representation of a particular node, including recursing through children
func dotNode(node *Node, builder *strings.Builder) {
	builder.WriteString(fmt.Sprintf("\"%x\"->\"%x\";", node.hash, node.left.hash))
	if node.left.IsLeaf() {
		builder.WriteString(fmt.Sprintf("\"%v\" [shape=oval];", node.left.data))
		builder.WriteString(fmt.Sprintf("\"%x\"->\"%v\";", node.left.hash, node.left.data))
	} else {
		dotNode(node.left, builder)
	}
	if node.right != node.left {
		builder.WriteString(fmt.Sprintf("\"%x\"->\"%x\";", node.hash, node.right.hash))
		if node.right.IsLeaf() {
			builder.WriteString(fmt.Sprintf("\"%v\" [shape=oval];", node.right.data))
			builder.WriteString(fmt.Sprintf("\"%x\"->\"%v\";", node.right.hash, node.right.data))
		} else {
			dotNode(node.right, builder)
		}
	}
}

// findLeafNode finds a leaf node with the provided data.  If there is no matching node then this returns nil.
func (t *MerkleTree) findLeafNode(data NodeData) *Node {
	hash := hashBytes(data.Bytes())
	node := t.root
	return findMatchingLeaf(node, hash)
}

// findMatchingLeaf is a recursive depth-first trawl through nodes to find the matching leaf node.
func findMatchingLeaf(node *Node, hash []byte) *Node {
	if node.IsLeaf() {
		leafHash := hashBytes(node.data.Bytes())
		if bytes.Equal(hash, leafHash) {
			return node
		}
		return nil
	}
	leftNode := findMatchingLeaf(node.left, hash)
	if leftNode != nil {
		return leftNode
	}
	return findMatchingLeaf(node.right, hash)
}

// regenerateHashes regenerates the hashes for the tree from a given node to the root.
func (t *MerkleTree) regenerateHashes(node *Node) {
	if node.IsLeaf() {
		node.hash = hashBytes(node.data.Bytes())
		t.regenerateHashes(node.parent)
	} else {
		node.hash = hashBytes(append(node.left.hash, node.right.hash...))
		if !node.IsRoot() {
			t.regenerateHashes(node.parent)
		}
	}
}
