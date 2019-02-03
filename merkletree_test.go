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
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wealdtech/go-merkletree/blake2b"
	"github.com/wealdtech/go-merkletree/keccak256"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

var tests = []struct {
	// hash type to use
	hashType HashType
	// data to create the node
	data [][]byte
	// expected error when attempting to create the tree
	createErr error
	// root hash after the tree has been created
	root []byte
	// DOT representation of tree
	dot string
	// salt to use
	salt []byte
	// saltedRoot hash after the tree has been created with the salt
	saltedRoot []byte
}{
	{ // 0
		hashType:  blake2b.New(),
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 1
		hashType:  blake2b.New(),
		data:      [][]byte{},
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 2
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
		},
		root:       _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
		dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"7b50…c81f\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"03c7…6406\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"e9e0…f637\"];}",
		salt:       []byte("salt"),
		saltedRoot: _byteArray("420ba02ad7ce2077a2f82f4ac3752eeaf1285779a210391e9378337af0ed3539"),
	},
	{ // 3
		hashType: keccak256.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
		},
		root:       _byteArray("fb6c3a47aacb11c3f7ee3717cfbd43e4ad08da66d2cb049358db7e056baaaeed"),
		dot:        "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->2;2 [label=\"b608…16b7\"];2->1;\"Bar\" [shape=oval];\"Bar\"->3;3 [label=\"c162…985f\"];2->3 [style=invisible arrowhead=none];3->1;{rank=same;2;3};1 [label=\"fb6c…aeed\"];}",
		salt:       []byte("salt"),
		saltedRoot: _byteArray("5d3112070164037e104b3cc42ef5242e35616fdc6d2b34e3605154a3e5f9d594"),
	},
	{ // 4
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
		},
		root: _byteArray("7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f"),
		dot:  "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->1;1 [label=\"7b50…c81f\"];{rank=same;1};}",
	},
	{ // 5
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
		},
		root: _byteArray("635ca493fe20a7b8485d2e4c650e33444664b4ce0773c36d2a9da79176f6889c"),
		dot:  "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->4;4 [label=\"7b50…c81f\"];4->2;\"Bar\" [shape=oval];\"Bar\"->5;5 [label=\"03c7…6406\"];4->5 [style=invisible arrowhead=none];5->2;\"Baz\" [shape=oval];\"Baz\"->6;6 [label=\"6d5f…2ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000…0000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"13c7…a929\"];3->1;2 [label=\"e9e0…f637\"];2->1;1 [label=\"635c…889c\"];}",
	},
	{ // 6
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
			[]byte("Qux"),
			[]byte("Quux"),
			[]byte("Quuz"),
		},
		root: _byteArray("4e6bdbaa326a760c45b5805898d7e9e788d65ffe7e27e690cd6999f1a5d64400"),
		dot:  "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->8;8 [label=\"7b50…c81f\"];8->4;\"Bar\" [shape=oval];\"Bar\"->9;9 [label=\"03c7…6406\"];8->9 [style=invisible arrowhead=none];9->4;\"Baz\" [shape=oval];\"Baz\"->10;10 [label=\"6d5f…2ae0\"];9->10 [style=invisible arrowhead=none];10->5;\"Qux\" [shape=oval];\"Qux\"->11;11 [label=\"d5d1…3cda\"];10->11 [style=invisible arrowhead=none];11->5;\"Quux\" [shape=oval];\"Quux\"->12;12 [label=\"2fec…1151\"];11->12 [style=invisible arrowhead=none];12->6;\"Quuz\" [shape=oval];\"Quuz\"->13;13 [label=\"aff2…62e5\"];12->13 [style=invisible arrowhead=none];13->6;14 [label=\"0000…0000\"];13->14 [style=invisible arrowhead=none];14->7;15 [label=\"0000…0000\"];14->15 [style=invisible arrowhead=none];15->7;{rank=same;8;9;10;11;12;13;14;15};7 [label=\"0e57…e3a8\"];7->3;6 [label=\"3705…4377\"];6->3;5 [label=\"f277…7fd5\"];5->2;4 [label=\"e9e0…f637\"];4->2;3 [label=\"7723…f470\"];3->1;2 [label=\"7799…9592\"];2->1;1 [label=\"4e6b…4400\"];}",
	},
	{ // 7
		hashType: blake2b.New(),
		data: [][]byte{
			[]byte("Foo"),
			[]byte("Bar"),
			[]byte("Baz"),
			[]byte("Qux"),
			[]byte("Quux"),
			[]byte("Quuz"),
			[]byte("FooBar"),
			[]byte("FooBaz"),
			[]byte("BarBaz"),
		},
		root: _byteArray("e15d86728d4a31c5880bc0d2d184637bb6672a72313af378141ea789f4b3929a"),
		dot:  "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"Foo\" [shape=oval];\"Foo\"->16;16 [label=\"7b50…c81f\"];16->8;\"Bar\" [shape=oval];\"Bar\"->17;17 [label=\"03c7…6406\"];16->17 [style=invisible arrowhead=none];17->8;\"Baz\" [shape=oval];\"Baz\"->18;18 [label=\"6d5f…2ae0\"];17->18 [style=invisible arrowhead=none];18->9;\"Qux\" [shape=oval];\"Qux\"->19;19 [label=\"d5d1…3cda\"];18->19 [style=invisible arrowhead=none];19->9;\"Quux\" [shape=oval];\"Quux\"->20;20 [label=\"2fec…1151\"];19->20 [style=invisible arrowhead=none];20->10;\"Quuz\" [shape=oval];\"Quuz\"->21;21 [label=\"aff2…62e5\"];20->21 [style=invisible arrowhead=none];21->10;\"FooBar\" [shape=oval];\"FooBar\"->22;22 [label=\"b1ae…72fc\"];21->22 [style=invisible arrowhead=none];22->11;\"FooBaz\" [shape=oval];\"FooBaz\"->23;23 [label=\"32d2…828e\"];22->23 [style=invisible arrowhead=none];23->11;\"BarBaz\" [shape=oval];\"BarBaz\"->24;24 [label=\"8173…a835\"];23->24 [style=invisible arrowhead=none];24->12;25 [label=\"0000…0000\"];24->25 [style=invisible arrowhead=none];25->12;26 [label=\"0000…0000\"];25->26 [style=invisible arrowhead=none];26->13;27 [label=\"0000…0000\"];26->27 [style=invisible arrowhead=none];27->13;28 [label=\"0000…0000\"];27->28 [style=invisible arrowhead=none];28->14;29 [label=\"0000…0000\"];28->29 [style=invisible arrowhead=none];29->14;30 [label=\"0000…0000\"];29->30 [style=invisible arrowhead=none];30->15;31 [label=\"0000…0000\"];30->31 [style=invisible arrowhead=none];31->15;{rank=same;16;17;18;19;20;21;22;23;24;25;26;27;28;29;30;31};15 [label=\"0e57…e3a8\"];15->7;14 [label=\"0e57…e3a8\"];14->7;13 [label=\"0e57…e3a8\"];13->6;12 [label=\"cff7…4135\"];12->6;11 [label=\"b12a…1342\"];11->5;10 [label=\"3705…4377\"];10->5;9 [label=\"f277…7fd5\"];9->4;8 [label=\"e9e0…f637\"];8->4;7 [label=\"8438…6412\"];7->3;6 [label=\"7578…713e\"];6->3;5 [label=\"2845…c279\"];5->2;4 [label=\"7799…9592\"];4->2;3 [label=\"84d1…1df2\"];3->1;2 [label=\"0d1f…d49e\"];2->1;1 [label=\"e15d…929a\"];}",
	},
}

func TestNew(t *testing.T) {
	for i, test := range tests {
		tree, err := NewUsing(test.data, test.hashType, nil)
		if test.createErr != nil {
			assert.Equal(t, test.createErr, err, fmt.Sprintf("expected error at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.root, tree.Root(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, tree.Root(), test.hashType, nil)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestSaltedProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.salt != nil {
			tree, err := NewUsing(test.data, test.hashType, test.salt)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.saltedRoot, tree.Root(), fmt.Sprintf("unexpected root at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, tree.Root(), test.hashType, test.salt)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestMissingProof(t *testing.T) {
	missingData := []byte("missing")
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, err = tree.GenerateProof(missingData)
			assert.Equal(t, err, errors.New("data not found"))
		}
	}

}

const _letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const _letterslen = len(_letters)

func _randomString(n int) string {
	res := make([]byte, n)
	for i := range res {
		res[i] = _letters[rand.Int63()%int64(_letterslen)]
	}
	return string(res)
}

func TestProofRandom(t *testing.T) {
	data := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		data[i] = []byte(_randomString(6))
	}
	tree, err := New(data)
	assert.Nil(t, err, "failed to create tree")
	for i := range data {
		proof, err := tree.GenerateProof(data[i])
		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
		proven, err := VerifyProof(data[i], proof, tree.Root())
		assert.True(t, proven, fmt.Sprintf("failed to verify proof at data %d", i))
	}
}

func TestString(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, fmt.Sprintf("%x", test.root), tree.String(), fmt.Sprintf("incorrect string representation at test %d", i))
		}
	}
}

func TestDOT(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, nil)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.dot, tree.DOT(new(StringFormatter), nil), fmt.Sprintf("incorrect DOT representation at test %d", i))
		}
	}
}

func TestFormatter(t *testing.T) {
	tree, err := New(tests[5].data)
	assert.Nil(t, err, "failed to create tree")
	assert.Equal(t, "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"466f…6f6f\" [shape=oval];\"466f…6f6f\"->4;4 [label=\"7b50…c81f\"];4->2;\"4261…6172\" [shape=oval];\"4261…6172\"->5;5 [label=\"03c7…6406\"];4->5 [style=invisible arrowhead=none];5->2;\"4261…617a\" [shape=oval];\"4261…617a\"->6;6 [label=\"6d5f…2ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000…0000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"13c7…a929\"];3->1;2 [label=\"e9e0…f637\"];2->1;1 [label=\"635c…889c\"];}", tree.DOT(nil, nil), "incorrect default representation")
	assert.Equal(t, "digraph MerkleTree {rankdir = BT;node [shape=rectangle margin=\"0.2,0.2\"];\"466f6f\" [shape=oval];\"466f6f\"->4;4 [label=\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"];4->2;\"426172\" [shape=oval];\"426172\"->5;5 [label=\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"];4->5 [style=invisible arrowhead=none];5->2;\"42617a\" [shape=oval];\"42617a\"->6;6 [label=\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\"];5->6 [style=invisible arrowhead=none];6->3;7 [label=\"0000000000000000000000000000000000000000000000000000000000000000\"];6->7 [style=invisible arrowhead=none];7->3;{rank=same;4;5;6;7};3 [label=\"13c75aad6074ad17d7014b1ee42012c840e90a79eb8e1694e3b107ca6ae8a929\"];3->1;2 [label=\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"];2->1;1 [label=\"635ca493fe20a7b8485d2e4c650e33444664b4ce0773c36d2a9da79176f6889c\"];}", tree.DOT(new(HexFormatter), new(HexFormatter)), "incorrect default representation")
}
