// Copyright © 2023 Weald Technology Trading.
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
	"errors"

	"github.com/wealdtech/go-merkletree/blake2b"
)

type parameters struct {
	data [][]byte
	salt bool
	hash HashType
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithData sets the data for the merkle tree.
func WithData(data [][]byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.data = data
	})
}

// WithSalt sets the salt for the merkle tree.
func WithSalt(salt bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.salt = salt
	})
}

// WithHashType sets the hash type for the merkle tree.
func WithHashType(hash HashType) Parameter {
	return parameterFunc(func(p *parameters) {
		p.hash = hash
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		hash: blake2b.New(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.hash == nil {
		return nil, errors.New("no hash type specified")
	}
	if len(parameters.data) == 0 {
		return nil, errors.New("tree must have at least 1 piece of data")
	}

	return &parameters, nil
}
