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
	"bytes"

	"github.com/wealdtech/go-merkletree/v2/blake2b"
)

// VerifyPollard ensures that the branches in the pollard match up with the root using the default hash type.
func VerifyPollard(pollard [][]byte) bool {
	return VerifyPollardUsing(pollard, blake2b.New())
}

// VerifyPollardUsing ensures that the branches in the pollard match up with the root using the supplied hash type.
func VerifyPollardUsing(pollard [][]byte, hashType HashType) bool {
	if len(pollard) == 1 {
		// If there is only a single hash it is automatically correct
		return true
	}
	for i := len(pollard)/2 - 1; i >= 0; i-- {
		if !bytes.Equal(pollard[i], hashType.Hash(pollard[i*2+1], pollard[i*2+2])) {
			return false
		}
	}

	return true
}
