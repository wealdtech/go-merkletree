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

	"github.com/wealdtech/go-merkletree/v2/blake2b"
)

type parameters struct {
	data    [][]byte
	values  uint64
	hashes  map[uint64][]byte
	indices []uint64
	salt    bool
	sorted  bool
	hash    HashType
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
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

// WithValues sets the values for the merkle proof.
func WithValues(values uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.values = values
	})
}

// WithHashes sets the indexed hashes of values that cannot be calculated from the proof.
func WithHashes(hashes map[uint64][]byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.hashes = hashes
	})
}

// WithIndices sets the indices that can be calculated from the proof.
func WithIndices(indices []uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.indices = indices
	})
}

// WithSalt sets the salt for the merkle tree or proof.
func WithSalt(salt bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.salt = salt
	})
}

// WithSorted sets the sorted for the merkle tree.
func WithSorted(sorted bool) Parameter {
	return parameterFunc(func(p *parameters) {
		p.sorted = sorted
	})
}

// WithHashType sets the hash type for the merkle tree or proof.
func WithHashType(hash HashType) Parameter {
	return parameterFunc(func(p *parameters) {
		p.hash = hash
	})
}

// parseAndCheckTreeParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckTreeParameters(params ...Parameter) (*parameters, error) {
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

	if parameters.values != 0 {
		return nil, errors.New("merkle tree does not use the values parameter")
	}
	if len(parameters.hashes) != 0 {
		return nil, errors.New("merkle tree does not use the hashes parameter")
	}
	if len(parameters.indices) != 0 {
		return nil, errors.New("merkle tree does not use the indices parameter")
	}

	return &parameters, nil
}

// parseAndCheckMultiProofParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckMultiProofParameters(params ...Parameter) (*parameters, error) {
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
	if parameters.values == 0 {
		return nil, errors.New("no values specified")
	}
	// Hashes can be empty.
	if len(parameters.indices) == 0 {
		return nil, errors.New("no indices specified")
	}

	if len(parameters.data) != 0 {
		return nil, errors.New("proof does not use the data parameter")
	}

	return &parameters, nil
}
