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

package merkletree

// Node is a node in the merkle tree.  It keeps track of parent and child relationships, along with the data if this is a leaf.
type Node struct {
	parent *Node
	left   *Node
	right  *Node
	hash   []byte
	data   NodeData
}

// IsLeaf returns true if the node is a leaf.  A leaf is defined as a node that has no children.
func (n *Node) IsLeaf() bool {
	return n.left == nil && n.right == nil
}

// IsRoot returns true if the node is the root.  The root is defined as a node that has no parent.
func (n *Node) IsRoot() bool {
	return n.parent == nil
}
