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

package blake2b

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}

func TestHash(t *testing.T) {
	var tests = []struct {
		data   []byte
		output []byte
		err    error
	}{
		{
			data:   _byteArray("e9e0083e456539e9f6336164cd98700e668178f98af147ef750eb90afcf2f637"),
			output: _byteArray("92c7a270abba6545cff680c3452f1573b3b672d66f663b4c1d1d3ce7c35b5170"),
		},
		{
			err: errors.New("no data supplied"),
		},
	}

	hash := New()
	for i, test := range tests {
		output, err := hash.Hash(test.data)
		if test.err != nil {
			assert.Equal(t, test.err, err, fmt.Sprintf("failed at test %d", i))
		} else {
			assert.Nil(t, err, fmt.Sprintf("unexpected error at test %d", i))
			assert.Equal(t, test.output, output, fmt.Sprintf("failed at test %d", i))
		}
	}
}
