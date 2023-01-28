package sha3

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashLength(t *testing.T) {
	assert.Equal(t, _256hashlength, New256().HashLength(), "incorrect hash length reported")
}

// _byteArray is a helper to turn a string in to a byte array
func _byteArray(input string) []byte {
	x, _ := hex.DecodeString(input)
	return x
}
