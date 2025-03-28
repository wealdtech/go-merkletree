package sha2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashLength(t *testing.T) {
	t.Parallel()
	assert.Equal(t, _256hashlength, New256().HashLength(), "incorrect hash length reported")
}
