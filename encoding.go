package merkletree

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/wealdtech/go-merkletree/v2/blake2b"
	"github.com/wealdtech/go-merkletree/v2/keccak256"
	"github.com/wealdtech/go-merkletree/v2/sha3"
)

// MarshalJSON implements json.Marshaler.
func (t *MerkleTree) MarshalJSON() ([]byte, error) {
	type ExportTree MerkleTree

	data, err := json.Marshal(&struct {
		HashType string `json:"hash_type"`
		*ExportTree
	}{
		HashType:   t.Hash.HashName(),
		ExportTree: (*ExportTree)(t),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal JSON")
	}

	return data, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *MerkleTree) UnmarshalJSON(data []byte) error {
	type ExportTree MerkleTree
	aux := &struct {
		HashType string `json:"hash_type"`
		*ExportTree
	}{
		ExportTree: (*ExportTree)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return errors.Wrap(err, "failed to unmarshal JSON")
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
