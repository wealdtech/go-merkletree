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

// testData is a structure that follows Data, allowing it to be stored in a Merkle tree
type testData struct {
	data string
}

// Bytes provides a byte array that represents the testData
func (t *testData) Bytes() []byte {
	return []byte(t.data)
}

// String implements the stringer interface
func (t *testData) String() string {
	return t.data
}

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

var tests = []struct {
	// hash type to use
	hashType HashType
	// data to create the node
	data []NodeData
	// expected error when attempting to create the tree
	createErr error
	// root hash after the tree has been created
	rootHash []byte
	// root hash after the first node in the tree has been replaced
	replaceHash []byte
	// DOT representation of tree
	dot string
}{
	{ // 0
		hashType:  blake2b.New(),
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 1
		hashType:  blake2b.New(),
		data:      []NodeData{},
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{ // 2
		hashType: blake2b.New(),
		data: []NodeData{
			&testData{
				data: "Foo",
			},
			&testData{
				data: "Bar",
			},
		},
		rootHash:    _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
		replaceHash: _byteArray("22f41fa6545fca4bf63ffa589d18cb96b15eac6d29ef00eda77259f379c7168c"),
		dot:         "digraph MerkleTree {node [shape=rectangle margin=\"0.2,0.2\"];\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\";\"Foo\" [shape=oval];\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"->\"Foo\";\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\";\"Bar\" [shape=oval];\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"->\"Bar\";}",
	},
	{ // 3
		hashType: keccak256.New(),
		data: []NodeData{
			&testData{
				data: "Foo",
			},
			&testData{
				data: "Bar",
			},
		},
		rootHash:    _byteArray("fb6c3a47aacb11c3f7ee3717cfbd43e4ad08da66d2cb049358db7e056baaaeed"),
		replaceHash: _byteArray("1d2b554ce29d3648cd9e3c59dcf76b4a884a73c472ae4b315c03edeb84f67986"),
		dot:         "digraph MerkleTree {node [shape=rectangle margin=\"0.2,0.2\"];\"fb6c3a47aacb11c3f7ee3717cfbd43e4ad08da66d2cb049358db7e056baaaeed\"->\"b608c74283f334e1f047dbbf1daa2407d41d4689aca67c422796f936acce16b7\";\"Foo\" [shape=oval];\"b608c74283f334e1f047dbbf1daa2407d41d4689aca67c422796f936acce16b7\"->\"Foo\";\"fb6c3a47aacb11c3f7ee3717cfbd43e4ad08da66d2cb049358db7e056baaaeed\"->\"c1620375a8984b68a8a35054aae54aa69d13022892c65c358427e8a2c391985f\";\"Bar\" [shape=oval];\"c1620375a8984b68a8a35054aae54aa69d13022892c65c358427e8a2c391985f\"->\"Bar\";}",
	},
	{ // 4
		hashType: blake2b.New(),
		data: []NodeData{
			&testData{
				data: "Foo",
			},
		},
		rootHash:    _byteArray("66dcea1632618af6a2a3f991fb8eac772cc9a92d6d24d3d53e303cfb7918ed3f"),
		replaceHash: _byteArray("c5ad026795f768b3a1a391c6fed2fd7a1cfe7f87ef7d3fafe5e3113906c5a3c1"),
		dot:         "digraph MerkleTree {node [shape=rectangle margin=\"0.2,0.2\"];\"66dcea1632618af6a2a3f991fb8eac772cc9a92d6d24d3d53e303cfb7918ed3f\"->\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\";\"Foo\" [shape=oval];\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"->\"Foo\";}",
	},
	{ // 5
		hashType: blake2b.New(),
		data: []NodeData{
			&testData{
				data: "Foo",
			},
			&testData{
				data: "Bar",
			},
			&testData{
				data: "Baz",
			},
		},
		rootHash:    _byteArray("4a7c101cd25d910af4c20030c0c52ba71a5c110554de4127a5a3cad03b13ea03"),
		replaceHash: _byteArray("a08f746db871db869251dbf86e72388b06054d3076fcf13f000b2803df5e284e"),
		dot:         "digraph MerkleTree {node [shape=rectangle margin=\"0.2,0.2\"];\"4a7c101cd25d910af4c20030c0c52ba71a5c110554de4127a5a3cad03b13ea03\"->\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\";\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\";\"Foo\" [shape=oval];\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"->\"Foo\";\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\";\"Bar\" [shape=oval];\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"->\"Bar\";\"4a7c101cd25d910af4c20030c0c52ba71a5c110554de4127a5a3cad03b13ea03\"->\"50cdef2fd6fd3c18ad0b10d52524d64a28f6f3216af68b46d79323bad2e4e728\";\"50cdef2fd6fd3c18ad0b10d52524d64a28f6f3216af68b46d79323bad2e4e728\"->\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\";\"Baz\" [shape=oval];\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\"->\"Baz\";}",
	},
	{ // 6
		hashType: blake2b.New(),
		data: []NodeData{
			&testData{
				data: "Foo",
			},
			&testData{
				data: "Bar",
			},
			&testData{
				data: "Baz",
			},
			&testData{
				data: "Qux",
			},
			&testData{
				data: "Quux",
			},
			&testData{
				data: "Quuz",
			},
		},
		rootHash:    _byteArray("9bbfa790a5c4c02f63b474e6e5d47410406fcc93449884dd59816f8557ac5d3e"),
		replaceHash: _byteArray("a7ed90b143723bc921568a3a2fb18e93c2cae7e0748122e2cab9815e3500676a"),
		dot:         "digraph MerkleTree {node [shape=rectangle margin=\"0.2,0.2\"];\"9bbfa790a5c4c02f63b474e6e5d47410406fcc93449884dd59816f8557ac5d3e\"->\"7799922ba259c0529cdfb9f974024d45abef9b3190850bc23fc5145cf81c9592\";\"7799922ba259c0529cdfb9f974024d45abef9b3190850bc23fc5145cf81c9592\"->\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\";\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\";\"Foo\" [shape=oval];\"7b506db718d5cce819ca4d33d2348065a5408cc89aa8b3f7ac70a0c186a2c81f\"->\"Foo\";\"e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637\"->\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\";\"Bar\" [shape=oval];\"03c70c07424c7d85174bf8e0dbd4600a4bd21c00ce34dea7ab57c83c398e6406\"->\"Bar\";\"7799922ba259c0529cdfb9f974024d45abef9b3190850bc23fc5145cf81c9592\"->\"f27788f150c5f45bb618f23034f12d3777f5348ec83ea75e3e81f467b9d67fd5\";\"f27788f150c5f45bb618f23034f12d3777f5348ec83ea75e3e81f467b9d67fd5\"->\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\";\"Baz\" [shape=oval];\"6d5fd2391f8abb79469edf404fd1751a74056ce54ee438c128bba9e680242ae0\"->\"Baz\";\"f27788f150c5f45bb618f23034f12d3777f5348ec83ea75e3e81f467b9d67fd5\"->\"d5d15f829b9736f8054c71c9ba480d1dca16f4575f6b805e3dd37cdc5aa33cda\";\"Qux\" [shape=oval];\"d5d15f829b9736f8054c71c9ba480d1dca16f4575f6b805e3dd37cdc5aa33cda\"->\"Qux\";\"9bbfa790a5c4c02f63b474e6e5d47410406fcc93449884dd59816f8557ac5d3e\"->\"8e42309e472ef8e84af84669decd20bcf2907fa5c69626b6f9cb34925426c594\";\"8e42309e472ef8e84af84669decd20bcf2907fa5c69626b6f9cb34925426c594\"->\"3705db8dede3991c0846bae4f9de86a2c5957283cdd3434337ee1bb98b2d4377\";\"3705db8dede3991c0846bae4f9de86a2c5957283cdd3434337ee1bb98b2d4377\"->\"2fec764e01bb41b8fcf07e93fa126fdb7419c8f5905c9149074a22f56f171151\";\"Quux\" [shape=oval];\"2fec764e01bb41b8fcf07e93fa126fdb7419c8f5905c9149074a22f56f171151\"->\"Quux\";\"3705db8dede3991c0846bae4f9de86a2c5957283cdd3434337ee1bb98b2d4377\"->\"aff2f20f3fd056c4ae59132fea6d5691fa7dc274ab13eef5e7cb06df856462e5\";\"Quuz\" [shape=oval];\"aff2f20f3fd056c4ae59132fea6d5691fa7dc274ab13eef5e7cb06df856462e5\"->\"Quuz\";}",
	},
}

func TestTreeNew(t *testing.T) {
	for i, test := range tests {
		tree, err := NewUsing(test.data, test.hashType)
		if test.createErr != nil {
			assert.Equal(t, test.createErr, err, fmt.Sprintf("expected error at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.rootHash, tree.RootHash(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestTreeFind(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				found, err := tree.ContainsData(data)
				assert.Nil(t, err, fmt.Sprintf("failed to check for data at test %d", i))
				assert.True(t, found, fmt.Sprintf("failed to find data at test %d data %d", i, j))
			}
		}
	}
}

func TestTreeReplace(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			// Replace an item
			replaceData := &testData{data: "replace"}
			err = tree.Replace(test.data[0], replaceData)
			assert.Nil(t, err, fmt.Sprintf("failed to replace data at test %d", i))
			assert.Equal(t, test.replaceHash, tree.RootHash(), fmt.Sprintf("unexpected root at test %d", i))
			// Revert the replacement
			err = tree.Replace(replaceData, test.data[0])
			assert.Nil(t, err, fmt.Sprintf("failed to replace data at test %d", i))
			assert.Equal(t, test.rootHash, tree.RootHash(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestTreeReplaceUnknown(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			// Attempt to replace a non-existant item
			bogusData := &testData{data: "not here"}
			replaceData := &testData{data: "replace"}
			err = tree.Replace(bogusData, replaceData)
			assert.Equal(t, errors.New("merkle tree does not contain this data"), err, fmt.Sprintf("unexpected error at test %d", i))
		}
	}
}

func TestTreeProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, path, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, proof, path, tree.RootHash(), test.hashType)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestTreeMissingData(t *testing.T) {
	missingData := &testData{
		data: "missing",
	}
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			found, err := tree.ContainsData(missingData)
			assert.Nil(t, err, fmt.Sprintf("failed to check for data at test %d", i))
			assert.False(t, found, fmt.Sprintf("found non-existant data at test %d", i))
		}
	}

}

func TestTreeMissingProof(t *testing.T) {
	missingData := &testData{
		data: "missing",
	}
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, _, err = tree.GenerateProof(missingData)
			assert.Equal(t, err, errors.New("merkle tree does not contain this data"))
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

func TestTreeProofRandom(t *testing.T) {
	data := make([]NodeData, 0)
	for i := 0; i < 1000; i++ {
		data = append(data, &testData{data: _randomString(6)})
	}
	tree, err := NewUsing(data, blake2b.New())
	assert.Nil(t, err, "failed to create tree")
	for i := range data {
		proof, path, err := tree.GenerateProof(data[i])
		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
		proven, err := VerifyProof(data[i], proof, path, tree.RootHash())
		assert.True(t, proven, fmt.Sprintf("failed to verify proof at data %d", i))
	}
}

func TestTreeString(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, fmt.Sprintf("%x", test.rootHash), tree.String(), fmt.Sprintf("incorrect string representation at test %d", i))
		}
	}
}

func TestTreeDOT(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.dot, tree.DOT(), fmt.Sprintf("incorrect DOT representation at test %d", i))
		}
	}
}
