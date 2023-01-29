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

package merkletree

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDOT(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
				WithSalt(test.salt),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.dot, tree.DOT(new(StringFormatter), nil), fmt.Sprintf("incorrect DOT representation at test %d", i))
		}
	}
}

func TestDOTProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
				WithSalt(test.salt),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.dot, tree.DOTProof(nil, new(StringFormatter), nil), fmt.Sprintf("incorrect DOT representation at test %d", i))
			for j := range test.proofDots {
				for k := range test.proofDots[j] {
					if test.proofDots[j][k] != "" {
						proof, err := tree.GenerateProof(test.data[j], k)
						assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d depth %d data %d", i, j, k))
						assert.Equal(t, test.proofDots[j][k], tree.DOTProof(proof, new(StringFormatter), nil), fmt.Sprintf("incorrect proof DOT representation at test %d depth %d data %d", i, j, k))
					}
				}
			}
		}
	}
}

func TestDOTMultiProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.multiProofDot != "" {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
				WithSalt(test.salt),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.dot, tree.DOTMultiProof(nil, new(StringFormatter), nil), fmt.Sprintf("incorrect DOT representation at test %d", i))
			proof, err := tree.GenerateMultiProof(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create multiproof at test %d", i))
			assert.Equal(t, test.multiProofDot, tree.DOTMultiProof(proof, new(StringFormatter), nil), fmt.Sprintf("incorrect multiproof DOT representation at test %d", i))
		}
	}
}

func TestFormatter(t *testing.T) {
	tree, err := New(tests[5].data)
	assert.Nil(t, err, "failed to create tree")
	assert.Equal(t, "digraph MerkleTree {rankdir = TB;node [shape=rectangle margin=\"0.2,0.2\"];\"466f…6f6f\" [shape=oval];\"466f…6f6f\"->4;4 [label=\"7b50…c81f\"];4->2;\"4261…6172\" [shape=oval];\"4261…6172\"->5;5 [label=\"03c7…6406\"];4->5 [style=invisible arrowhead=none];5->2;\"4261…617a\" [shape=oval];\"4261…617a\"->6;6 [label=\"6d5f…2ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000…0000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"113f…1135\"];3->1;2 [label=\"e9e0…f637\"];2->1;1 [label=\"2c95…4203\"];}", tree.DOT(nil, nil), "incorrect default representation")
	assert.Equal(t, "digraph MerkleTree {rankdir = TB;node [shape=rectangle margin=\"0.2,0.2\"];\"466f6f\" [shape=oval];\"466f6f\"->4;4 [label=\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"];4->2;\"426172\" [shape=oval];\"426172\"->5;5 [label=\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"];4->5 [style=invisible arrowhead=none];5->2;\"42617a\" [shape=oval];\"42617a\"->6;6 [label=\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000000000000000000000000000000000000000000000000000000000000000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"113f21ad3be5252e487795473d5e0e221fddf3daee6b5596635428e5feaa1135\"];3->1;2 [label=\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"];2->1;1 [label=\"2c95331b1a38dba3600391a3e864f9418a271388936e54edecd916824bb54203\"];}", tree.DOT(new(HexFormatter), new(HexFormatter)), "incorrect default representation")
}
