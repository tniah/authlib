package requests

import (
	"github.com/stretchr/testify/assert"
	autherrors "github.com/tniah/authlib/errors"
	"testing"
)

func TestValidateDisplay(t *testing.T) {
	r := AuthorizationRequest{}
	err := r.ValidateDisplay(true)
	assert.Error(t, err)
	authErr, err := autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, ErrMissingDisplay, authErr.Description)

	err = r.ValidateDisplay(false)
	assert.NoError(t, err)

	r.Display = "test"
	err = r.ValidateDisplay(true)
	assert.Error(t, err)
	authErr, err = autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, ErrInvalidDisplay, authErr.Description)

	err = r.ValidateDisplay(false)
	assert.Error(t, err)
	authErr, err = autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, ErrInvalidDisplay, authErr.Description)

	r.Display = DisplayTouch
	err = r.ValidateDisplay(true)
	assert.Nil(t, err)
}
