package merkletree

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"github.com/wealdtech/go-merkletree/sha3"
	"testing"
)

func TestEncoding(t *testing.T) {
	hashType := sha3.New512()

	data := [][]byte{
		[]byte("Foo"),
		[]byte("Bar"),
	}

	tree, err := NewTree(
		WithData(data),
		WithHashType(hashType),
	)
	require.NoError(t, err)

	exported, err := json.Marshal(tree)
	require.NoError(t, err)

	var newTree MerkleTree
	err = json.Unmarshal(exported, &newTree)
	require.NoError(t, err)

	require.Equal(t, tree.Root(), newTree.Root())

}
