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

package merkletree

// HashFunc is a hashing function.
type HashFunc func(...[]byte) []byte

// HashType defines the interface that must be supplied by hash functions.
type HashType interface {
	// Hash calculates the hash of a given input.
	Hash(data ...[]byte) []byte

	// HashName returns the name of the hashing algorithm to be used in encoding
	HashName() string

	// HashLength provides the length of the hash.
	HashLength() int
}
