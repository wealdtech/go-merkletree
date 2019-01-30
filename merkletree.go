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
// create a tree and generate and verify proofs.  The hashing algorithm for the tree is selectable between BLAKE2b and Keccak256.
//
// Creating a Merkle tree requires a list of objects that implement the NodeData interface.  Once a tree has been created proofs
// can be generated using the tree's GenerateProof() function.
//
// The package includes a function to verify a generated proof given only the data, proof and the root hash of the relevant Merkle
// tree.  This allows for efficient verification of proofs without requiring the entire Merkle tree to be stored or recreated.
//
// Implementation notes
//
// If there is an odd number of nodes at any level in the tree (except the root) the last node is used as both left and right nodes
// when generating the hash for the parent node.
package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/wealdtech/go-merkletree/blake2b"
)

// MerkleTree is the top-level structure for the merkle tree.
type MerkleTree struct {
	// hash is a pointer to the hashing struct
	hash HashFunc
	// depth is the number of levels in the tree, including the root and leaf levels
	depth int
	root  *Node
}

// ContainsData returns true if the tree contains the provided data, otherwise false.
func (t *MerkleTree) ContainsData(data NodeData) (bool, error) {
	node, err := t.findLeafNode(data)
	if err != nil {
		return false, err
	}
	return node != nil, err
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
func (t *MerkleTree) GenerateProof(data NodeData) (*Proof, error) {
	// Find the path to the node containing the data
	path, err := t.pathToLeaf(data)
	if err != nil {
		return nil, err
	}
	if path == nil {
		return nil, errors.New("merkle tree does not contain this data")
	}
	proof := make([][]byte, len(path)-1)
	proofPath := make([]bool, len(path)-1)

	for i := 1; i < len(path); i++ {
		if path[i-1].Left == path[i] {
			// We want the right-hand node
			proof[len(path)-i-1] = path[i-1].Right.Hash
			proofPath[len(path)-i-1] = false
		} else {
			// We want the left-hand node
			proof[len(path)-i-1] = path[i-1].Left.Hash
			proofPath[len(path)-i-1] = true
		}
	}
	return newProof(proof, proofPath), nil
}

// NewFromRaw creates a new Merkle tree using the provided raw data and default hash type.
// data must contain at least one element for it to be valid.
func NewFromRaw(rawData [][]byte) (*MerkleTree, error) {
	return NewFromRawUsing(rawData, blake2b.New())
}

// NewFromRawUsing creates a new Merkle tree using the provided raw data and supplied hash type.
// data must contain at least one element for it to be valid.
func NewFromRawUsing(rawData [][]byte, hash HashType) (*MerkleTree, error) {
	if len(rawData) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	tree := &MerkleTree{
		hash: hash.Hash,
	}

	// Turn the node data in to leaf nodes
	nodes := make([]Node, len(rawData))
	for i, data := range rawData {
		hash, err := tree.hash(data)
		if err != nil {
			return nil, err
		}
		nodes[i].Hash = hash
		nodes[i].Data = ByteArrayData(data)
	}

	// Iterate up the tree until only one node is returned
	branches := &nodes
	for {
		branches = tree.buildBranches(branches)
		if len(*branches) == 1 {
			break
		}
	}
	tree.root = &(*branches)[0]

	// Calculate depth of tree
	depth := 1
	for tmp := tree.root; tmp.Left != nil; tmp = tmp.Left {
		depth++
	}
	tree.depth = depth

	return tree, nil
}

// New creates a new Merkle tree using the provided data and default hash type.
// nodeData must contain at least one element for it to be valid.
func New(nodeData []NodeData) (*MerkleTree, error) {
	return NewUsing(nodeData, blake2b.New())
}

// NewUsing creates a new Merkle tree using the provided data and hash type.
// nodeData must contain at least one element for it to be valid.
func NewUsing(nodeData []NodeData, hash HashType) (*MerkleTree, error) {
	if len(nodeData) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	tree := &MerkleTree{
		hash: hash.Hash,
	}

	// Turn the node data in to leaf nodes
	nodes := make([]Node, len(nodeData))
	for i, data := range nodeData {
		hash, err := tree.hash(data.Bytes())
		if err != nil {
			return nil, err
		}
		nodes[i].Hash = hash
		nodes[i].Data = data
	}

	// Iterate up the tree until only one node is returned
	branches := &nodes
	for {
		branches = tree.buildBranches(branches)
		if len(*branches) == 1 {
			break
		}
	}
	tree.root = &(*branches)[0]

	// Calculate depth of tree
	depth := 1
	for tmp := tree.root; tmp.Left != nil; tmp = tmp.Left {
		depth++
	}
	tree.depth = depth

	return tree, nil
}

// RootHash returns the Merkle root (hash of the root node) of the tree.
func (t *MerkleTree) RootHash() []byte {
	return t.root.Hash
}

// Root returns the root node of the tree.
func (t *MerkleTree) Root() *Node {
	return t.root
}

// String implements the stringer interface
func (t *MerkleTree) String() string {
	return fmt.Sprintf("%x", t.root.Hash)
}

// buildBranches builds the branch nodes for a list of nodes.  The nodes passed in can be leaves or branches.
// This is used by New() to construct the non-leaf nodes.
func (t *MerkleTree) buildBranches(nodesPtr *[]Node) *[]Node {
	nodes := *nodesPtr
	var parentNodes []Node
	if len(nodes)%2 == 1 {
		parentNodes = make([]Node, len(nodes)/2+1)
	} else {
		parentNodes = make([]Node, len(nodes)/2)
	}
	for i := 0; i < len(nodes); i += 2 {
		parentNode := &parentNodes[i/2]
		leftNode := nodes[i]
		var rightNode Node
		if len(nodes) == i+1 {
			// We have an odd nuber of nodes; use the left-hand node as both nodes to make it even
			rightNode = nodes[i]
		} else {
			rightNode = nodes[i+1]
		}
		parentNode.Hash, _ = t.hash(append(leftNode.Hash, rightNode.Hash...))
		// TODO swallowing error
		parentNode.Left = &leftNode
		parentNode.Right = &rightNode
	}
	return &parentNodes
}

// dotNode creates a DOT representation of a particular node, including recursing through children
func dotNode(node *Node, builder *strings.Builder) {
	builder.WriteString(fmt.Sprintf("\"%x\"->\"%x\";", node.Hash, node.Left.Hash))
	if node.Left.IsLeaf() {
		builder.WriteString(fmt.Sprintf("\"%v\" [shape=oval];", node.Left.Data))
		builder.WriteString(fmt.Sprintf("\"%x\"->\"%v\";", node.Left.Hash, node.Left.Data))
	} else {
		dotNode(node.Left, builder)
	}
	if node.Right.String() != node.Left.String() {
		builder.WriteString(fmt.Sprintf("\"%x\"->\"%x\";", node.Hash, node.Right.Hash))
		if node.Right.IsLeaf() {
			builder.WriteString(fmt.Sprintf("\"%v\" [shape=oval];", node.Right.Data))
			builder.WriteString(fmt.Sprintf("\"%x\"->\"%v\";", node.Right.Hash, node.Right.Data))
		} else {
			dotNode(node.Right, builder)
		}
	}
}

// pathToLeaf provides the path from the root to the leaf with the provided data.
// If there is no matching node this returns nil
func (t *MerkleTree) pathToLeaf(data NodeData) ([]*Node, error) {
	hash, err := t.hash(data.Bytes())
	if err != nil {
		return nil, err
	}
	node := t.root
	path := make([]*Node, t.depth)
	found, err := t.pathToLeafNode(node, hash, &path, 0)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return path, nil
}

// pathToLeafNode is a recursive depth-first trawl through nodes to generate the path of branches from the root to the given node.
// The path does not include the root or the leaf
func (t *MerkleTree) pathToLeafNode(node *Node, hash []byte, path *[]*Node, level int) (bool, error) {
	if node.IsLeaf() {
		if bytes.Equal(hash, node.Hash) {
			(*path)[level] = node
			return true, nil
		}
		return false, nil
	}
	found, err := t.pathToLeafNode(node.Left, hash, path, level+1)
	if err != nil {
		return false, err
	}
	if found {
		(*path)[level] = node
		return found, nil
	}
	found, err = t.pathToLeafNode(node.Right, hash, path, level+1)
	if err != nil {
		return false, err
	}
	if found {
		(*path)[level] = node
	}
	return found, nil
}

// findLeafNode finds a leaf node with the provided data.  If there is no matching node then this returns nil.
func (t *MerkleTree) findLeafNode(data NodeData) (*Node, error) {
	hash, err := t.hash(data.Bytes())
	if err != nil {
		return nil, err
	}
	node := t.root
	return t.findMatchingLeaf(node, hash)
}

// findMatchingLeaf is a recursive depth-first trawl through nodes to find the matching leaf node.
func (t *MerkleTree) findMatchingLeaf(node *Node, hash []byte) (*Node, error) {
	if node.IsLeaf() {
		if bytes.Equal(hash, node.Hash) {
			return node, nil
		}
		return nil, nil
	}
	leftNode, err := t.findMatchingLeaf(node.Left, hash)
	if err != nil {
		return nil, err
	}
	if leftNode != nil {
		return leftNode, nil
	}
	return t.findMatchingLeaf(node.Right, hash)
}
