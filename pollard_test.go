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
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimplePollard(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.pollards != nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j := 0; j < int(math.Ceil(math.Log2(float64(len(test.data))))); j++ {
				pollard := tree.Pollard(j)
				assert.True(t, VerifyPollard(pollard), fmt.Sprintf("incorrect pollard at at test %d height %d", i, j))
			}
		}
	}
}

func TestPollard(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.pollards != nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j := 0; j < int(math.Ceil(math.Log2(float64(len(test.data))))); j++ {
				pollard := tree.Pollard(j)
				assert.Equal(t, test.pollards[j], pollard, fmt.Sprintf("incorrect pollard at at test %d height %d", i, j))
				assert.True(t, VerifyPollardUsing(pollard, test.hashType), fmt.Sprintf("incorrect pollard at at test %d height %d", i, j))
			}
		}
	}
}

func TestBadPollard(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && test.pollards != nil {
			tree, err := NewUsing(test.data, test.hashType, false)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			for j := 0; j < int(math.Ceil(math.Log2(float64(len(test.data))))); j++ {
				pollard := tree.Pollard(j)
				if len(pollard) > 1 {
					copy(pollard[0], []byte{0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad})
					assert.False(t, VerifyPollardUsing(pollard, test.hashType), fmt.Sprintf("incorrect pollard at at test %d height %d", i, j))
				}
			}
		}
	}
}
