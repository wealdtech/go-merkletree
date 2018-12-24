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

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testData is a structure that follows Data, allowing it to be stored in a Merkle tree
type testData struct {
	data string
}

// Bytes provides a byte array that represents the testData
func (t *testData) Bytes() []byte {
	return []byte(t.data)
}

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

var tests = []struct {
	data      []NodeData
	createErr error
	rootHash  []byte
}{
	{
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{
		data:      []NodeData{},
		createErr: errors.New("tree must have at least 1 piece of data"),
	},
	{
		data: []NodeData{
			&testData{
				data: "Foo",
			},
			&testData{
				data: "Bar",
			},
		},
		rootHash: _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
	},
	{
		data: []NodeData{
			&testData{
				data: "Foo",
			},
		},
		rootHash: _byteArray("66dcea1632618af6a2a3f991fb8eac772cc9a92d6d24d3d53e303cfb7918ed3f"),
	},
	{
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
		rootHash: _byteArray("4a7c101cd25d910af4c20030c0c52ba71a5c110554de4127a5a3cad03b13ea03"),
	},
	{
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
		rootHash: _byteArray("9bbfa790a5c4c02f63b474e6e5d47410406fcc93449884dd59816f8557ac5d3e"),
	},
}

func TestNew(t *testing.T) {
	for i, test := range tests {
		tree, err := New(test.data)
		if test.createErr != nil {
			assert.Equal(t, test.createErr, err, fmt.Sprintf("expected error at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.rootHash, tree.RootHash(), fmt.Sprintf("unexpected root at test %d", i))
		}
	}
}

func TestFind(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := New(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				assert.True(t, tree.ContainsData(data), fmt.Sprintf("failed to find data at test %d data %d", i, j))
			}
		}
	}
}

func TestProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := New(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, path, err := tree.GenerateProof(data)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				assert.True(t, VerifyProof(data, proof, path, tree.RootHash()), fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestMissingData(t *testing.T) {
	missingData := &testData{
		data: "missing",
	}
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := New(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.False(t, tree.ContainsData(missingData), fmt.Sprintf("found non-existant data at test %d", i))
		}
	}

}

func TestMissingProof(t *testing.T) {
	missingData := &testData{
		data: "missing",
	}
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := New(test.data)
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

func TestProofRandom(t *testing.T) {
	data := make([]NodeData, 0)
	for i := 0; i < 1000; i++ {
		data = append(data, &testData{data: _randomString(6)})
	}
	tree, err := New(data)
	assert.Nil(t, err, "failed to create tree")
	for i := range data {
		proof, path, err := tree.GenerateProof(data[i])
		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
		assert.True(t, VerifyProof(data[i], proof, path, tree.RootHash()), fmt.Sprintf("failed to verify proof at data %d", i))
	}
}

func TestString(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := New(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, fmt.Sprintf("%x", test.rootHash), tree.String(), fmt.Sprintf("incorrect string representation at test %d", i))
		}
	}
}
