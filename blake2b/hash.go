// Copyright © 2019 Weald Technology Trading
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
	"golang.org/x/crypto/blake2b"
)

// BLAKE2b is the Blake2b hashing method
type BLAKE2b struct{}

// New creates a new Blake2b hashing method
func New() *BLAKE2b {
	return &BLAKE2b{}
}

// Hash generates a BLAKE2b hash from a byte array
func (h *BLAKE2b) Hash(data []byte) []byte {
	hash := blake2b.Sum256(data)
	return hash[:]
}
