package merkletree

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTreeParameters(t *testing.T) {
	p, err := parseAndCheckTreeParameters(
		WithHashType(nil),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "no hash type specified")

	p, err = parseAndCheckTreeParameters()
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "tree must have at least 1 piece of data")

	p, err = parseAndCheckTreeParameters(
		WithData([][]byte{{'a'}}),
		WithValues(1),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "merkle tree does not use the values parameter")

	p, err = parseAndCheckTreeParameters(
		WithData([][]byte{{'a'}}),
		WithHashes(map[uint64][]byte{0: {'a'}}),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "merkle tree does not use the hashes parameter")

	p, err = parseAndCheckTreeParameters(
		WithData([][]byte{{'a'}}),
		WithIndices([]uint64{0}),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "merkle tree does not use the indices parameter")

	p, err = parseAndCheckMultiProofParameters(
		WithHashType(nil),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "no hash type specified")

	p, err = parseAndCheckMultiProofParameters()
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "no values specified")

	p, err = parseAndCheckMultiProofParameters(
		WithValues(1),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "no indices specified")

	p, err = parseAndCheckMultiProofParameters(
		WithValues(1),
		WithIndices([]uint64{0}),
		WithData([][]byte{{'a'}}),
	)
	assert.Nil(t, p, "prams should be nil on error")
	assert.Equal(t, err.Error(), "proof does not use the data parameter")
}
