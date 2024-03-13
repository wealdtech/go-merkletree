// Copyright © 2018 - 2023 Weald Technology Trading.
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
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiProofWithIndices(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
				WithSalt(test.salt),
				WithSorted(test.sorted),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))

			// Test proof for all combinations of data.
			var proof *MultiProof
			combinations := 1<<len(tree.Data) - 1
			for j := 1; j <= combinations; j++ {
				indices := make([]uint64, 0)
				items := make([][]byte, 0)
				for k := 0; k < len(tree.Data); k++ {
					if (j>>k)&1 == 1 {
						indices = append(indices, uint64(k))
						items = append(items, tree.Data[k])
					}
				}
				proof, err = tree.GenerateMultiProofWithIndices(indices)
				assert.Nil(t, err, fmt.Sprintf("failed to create multiproof at test %d data %d", i, j))
				proven, err := proof.Verify(items, tree.Root())
				assert.Nil(t, err, fmt.Sprintf("error verifying multiproof at test %d data %d", i, j))
				assert.True(t, proven, fmt.Sprintf("failed to verify multiproof at test %d data %d", i, j))
			}
		}
	}
}

func TestMultiProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
				WithSalt(test.salt),
				WithSorted(test.sorted),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))

			// Test proof for all combinations of data.
			var proof *MultiProof
			combinations := 1<<len(test.data) - 1
			for j := 1; j <= combinations; j++ {
				items := make([][]byte, 0)
				for k := 0; k < len(test.data); k++ {
					if (j>>k)&1 == 1 {
						items = append(items, test.data[k])
					}
				}
				proof, err = tree.GenerateMultiProof(items)
				assert.Nil(t, err, fmt.Sprintf("failed to create multiproof at test %d data %d", i, j))
				proven, err := proof.Verify(items, tree.Root())
				assert.Nil(t, err, fmt.Sprintf("error verifying multiproof at test %d data %d", i, j))
				assert.True(t, proven, fmt.Sprintf("failed to verify multiproof at test %d data %d", i, j))
			}
		}
	}
}

func TestMissingMultiProof(t *testing.T) {
	missingData := [][]byte{[]byte("missing")}
	for i, test := range tests {
		if test.createErr == nil {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))
			_, err = tree.GenerateMultiProof(missingData)
			assert.Equal(t, err.Error(), "data not found")
		}
	}
}

func TestBadMultiProof(t *testing.T) {
	for i, test := range tests {
		if test.createErr == nil && len(test.data) > 1 {
			tree, err := NewTree(
				WithData(test.data),
				WithHashType(test.hashType),
			)
			assert.Nil(t, err, fmt.Sprintf("failed to create tree at test %d", i))

			proof, err := tree.GenerateMultiProof(test.data)
			assert.Nil(t, err, fmt.Sprintf("failed to create multiproof at test %d", i))
			if len(proof.Hashes) > 0 {
				for k := range proof.Hashes {
					copy(proof.Hashes[k], []byte{0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad, 0x0b, 0xad})
				}
				proven, err := VerifyMultiProofUsing(test.data, false, proof, tree.Root(), test.hashType)
				assert.Nil(t, err, fmt.Sprintf("error verifying proof at test %d", i))
				assert.False(t, proven, fmt.Sprintf("incorrectly verified proof at test %d", i))
			}
		}
	}
}

func TestMultiProofRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	dataItems := 4096
	proofs := 128
	data := make([][]byte, dataItems)
	for i := 0; i < dataItems; i++ {
		data[i] = []byte(_randomString(6))
	}
	tree, err := New(data)
	assert.Nil(t, err, "failed to create tree")

	rand.Seed(0)
	for i := 0; i < 100; i++ {
		indices := make([]uint64, proofs)
		proofData := make([][]byte, proofs)
		for j := 0; j < proofs; j++ {
			indices[j] = uint64(rand.Int31n(int32(dataItems)))
			proofData[j] = data[indices[j]]
		}
		multiProof, err := tree.GenerateMultiProof(proofData)
		assert.Nil(t, err, fmt.Sprintf("error creating multiproof at test %d", i))

		proven, err := VerifyMultiProof(proofData, false, multiProof, tree.Root())
		assert.Nil(t, err, fmt.Sprintf("error verifying multiproof at test %d", i))
		assert.True(t, proven, fmt.Sprintf("failed to verify multiproof at test %d", i))
	}
}

func TestSavings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	if !testing.Verbose() {
		t.Skip("skipping test in non-verbose mode")
	}
	dataItems := 65536
	proofs := 128
	data := make([][]byte, dataItems)
	for i := 0; i < dataItems; i++ {
		data[i] = []byte(_randomString(6))
	}
	tree, err := New(data)
	assert.Nil(t, err, "failed to create tree")

	rand := rand.New(rand.NewSource(0))
	proofSize := 0
	pollardSize := 0
	multiProofSize := 0
	for i := 0; i < 100; i++ {
		indices := make([]uint64, proofs)
		proofData := make([][]byte, proofs)
		for j := 0; j < proofs; j++ {
			indices[j] = uint64(rand.Int31n(int32(dataItems)))
			proofData[j] = data[indices[j]]
		}

		// Simple proofs
		simpleProofs := &struct {
			Root   []byte
			Proofs []Proof
		}{
			Root:   tree.Root(),
			Proofs: make([]Proof, len(indices)),
		}
		for j := range indices {
			proof, err := tree.GenerateProof(proofData[j], 0)
			require.Nil(t, err, fmt.Sprintf("failed to create proof at test %d", i))
			simpleProofs.Proofs[j] = *proof
		}
		bytes, err := json.Marshal(simpleProofs)
		require.Nil(t, err, fmt.Sprintf("failed to create JSON at test %d", i))
		proofSize += len(bytes)

		// Pollarded proofs
		level := int(math.Floor(math.Log2(float64(len(indices)))))
		pollardProofs := &struct {
			Pollard [][]byte
			Proofs  []Proof
		}{
			Pollard: tree.Pollard(level),
			Proofs:  make([]Proof, len(indices)),
		}
		for j := range indices {
			proof, err := tree.GenerateProof(proofData[j], level)
			require.Nil(t, err, fmt.Sprintf("failed to create proof at test %d", i))
			pollardProofs.Proofs[j] = *proof
		}
		bytes, err = json.Marshal(pollardProofs)
		require.Nil(t, err, fmt.Sprintf("failed to create JSON at test %d", i))
		pollardSize += len(bytes)

		// Multiproof
		multiProof, err := tree.GenerateMultiProof(proofData)
		assert.Nil(t, err, fmt.Sprintf("failed to create multiproof at test %d", i))
		bytes, err = json.Marshal(multiProof)
		require.Nil(t, err, fmt.Sprintf("failed to create JSON at test %d", i))
		multiProofSize += len(bytes)
	}

	t.Log(fmt.Sprintf("Pollard size over simple proofs:\t%d/%d\t=>\t%2.2f%% saving", pollardSize, proofSize, float32(100)-float32(pollardSize*100)/float32(proofSize)))
	t.Log(fmt.Sprintf("Multiproof size over simple proofs:\t%d/%d\t=>\t%2.2f%% saving", multiProofSize, proofSize, float32(100)-float32(multiProofSize*100)/float32(proofSize)))
	t.Log(fmt.Sprintf("Multiproof size over pollard:\t%d/%d\t=>\t%2.2f%% saving", multiProofSize, pollardSize, float32(100)-float32(multiProofSize*100)/float32(pollardSize)))
}
