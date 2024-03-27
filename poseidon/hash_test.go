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

package poseidon_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wealdtech/go-merkletree/v2/poseidon"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return x
}

func TestHash(t *testing.T) {
	tests := []struct {
		data   []byte
		output []byte
	}{
		{
			data:   _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
			output: _byteArray("05c26e4fd0b4cbf27aa04a2f7934afc086bfb20e9d431f7c50b7e5cc5ea07a02"),
		},
	}

	hash := poseidon.New()
	assert.Equal(t, "poseidon", hash.HashName())
	for i, test := range tests {
		output := hash.Hash(test.data)
		assert.Equal(t, test.output, output, fmt.Sprintf("failed at test %d", i))
	}
}

func TestMultiHash(t *testing.T) {
	tests := []struct {
		data1  []byte
		data2  []byte
		data3  []byte
		data4  []byte
		output []byte
	}{
		{
			data1:  _byteArray("e9e0083e456539e9"),
			data2:  _byteArray("f6336164cd98700e"),
			data3:  _byteArray("668178f98af147ef"),
			data4:  _byteArray("750eb90afcf2f637"),
			output: _byteArray("05c26e4fd0b4cbf27aa04a2f7934afc086bfb20e9d431f7c50b7e5cc5ea07a02"),
		},
	}

	hash := poseidon.New()
	for i, test := range tests {
		output := hash.Hash(test.data1, test.data2, test.data3, test.data4)
		assert.Equal(t, test.output, output, fmt.Sprintf("failed at test %d", i))
	}
}
