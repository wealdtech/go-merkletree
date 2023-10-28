package merkletree

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/wealdtech/go-merkletree/blake2b"
	"github.com/wealdtech/go-merkletree/keccak256"
	"github.com/wealdtech/go-merkletree/sha3"
)

func (t *MerkleTree) MarshalJSON() ([]byte, error) {
	type ExportTree MerkleTree

	return json.Marshal(&struct {
		HashType string `json:"hash_type"`
		*ExportTree
	}{
		HashType:   t.Hash.HashName(),
		ExportTree: (*ExportTree)(t),
	})
}

func (t *MerkleTree) UnmarshalJSON(data []byte) error {
	type ExportTree MerkleTree
	aux := &struct {
		HashType string `json:"hash_type"`
		*ExportTree
	}{
		ExportTree: (*ExportTree)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch aux.HashType {
	case "sha512":
		aux.Hash = sha3.New512()
	case "sha256":
		aux.Hash = sha3.New256()
	case "blake2b":
		aux.Hash = blake2b.New()
	case "keccak256":
		aux.Hash = keccak256.New()
	default:
		return errors.New("cannot parse hash type")
	}

	return nil
}
