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

package keccak256

import (
	"golang.org/x/crypto/sha3"
)

type Keccak256 struct{}

func New() *Keccak256 {
	return &Keccak256{}
}

// Hash generates a Keccak-256 hash from a byte array
func (h *Keccak256) Hash(data []byte) ([]byte, error) {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil), nil
}
