package requests

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsRequired(t *testing.T) {
	ret := isRequired(false, true)
	assert.Equal(t, true, ret)

	ret = isRequired(false, false)
	assert.Equal(t, false, ret)

	ret = isRequired(false)
	assert.Equal(t, false, ret)

	ret = isRequired(true)
	assert.Equal(t, true, ret)
}
