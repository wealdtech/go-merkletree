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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data, 0)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, false, proof, [][]byte{tree.Root()}, test.hashType)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestSaltedProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.salt {
			tree, err := NewUsing(test.data, test.hashType, test.salt)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			assert.Equal(t, test.salt, tree.Salt(), fmt.Sprintf("unexpected salt at test %d", i))
			assert.Equal(t, test.saltedRoot, tree.Root(), fmt.Sprintf("unexpected root at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data, 0)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				proven, err := VerifyProofUsing(data, test.salt, proof, [][]byte{tree.Root()}, test.hashType)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d", i, j))
			}
		}
	}
}

func TestPollardProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.pollards != nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				for k := range test.pollards {
					pollard := tree.Pollard(k)
					assert.Equal(t, test.pollards[k], pollard, fmt.Sprintf("failed to create pollard at test %d data %d pollard %d", i, j, k))
					proof, err := tree.GenerateProof(data, k)
					assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d pollard %d", i, j, k))
					proven, err := VerifyProofUsing(data, false, proof, pollard, test.hashType)
					assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d data %d pollard %d", i, j, k))
					assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d data %d pollard %d", i, j, k))
				}
			}
		}
	}
}

func TestMissingProof(t *testing.T) {
	missingData := []byte("missing")
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, err = tree.GenerateProof(missingData, 0)
			assert.Equal(t, err.Error(), "data not found")
		}
	}
}

func TestBadProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && len(test.data) > 1 {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j, data := range test.data {
				proof, err := tree.GenerateProof(data, 0)
				assert.Nil(t, err, fmt.Sprintf("failed to create proof at test %d data %d", i, j))
				copy(proof.Hashes[0], []byte{0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad})
				proven, err := VerifyProofUsing(data, false, proof, [][]byte{tree.Root()}, test.hashType)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d data %d", i, j))
				assert.False(t, proven, fmt.Sprintf("incorrectly verified proof at test %d data %d", i, j))
			}
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
		proof, err := tree.GenerateProof(data[i], 0)
		assert.Nil(t, err, fmt.Sprintf("failed to create proof at data %d", i))
		proven, err := VerifyProof(data[i], false, proof, [][]byte{tree.Root()})
		assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
		assert.True(t, proven, fmt.Sprintf("failed to verify proof at test %d", i))
	}
}
