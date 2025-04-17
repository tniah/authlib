package requests

import (
	"github.com/stretchr/testify/assert"
	"github.com/tniah/authlib/attributes"
	autherrors "github.com/tniah/authlib/errors"
	"testing"
)

func TestValidateDisplay(t *testing.T) {
	r := AuthorizationRequest{}
	err := r.ValidateDisplay(true)
	assert.Error(t, err)
	authErr, err := autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, "missing \"display\" in request", authErr.Description)

	err = r.ValidateDisplay(false)
	assert.NoError(t, err)

	r.Display = "test"
	err = r.ValidateDisplay(true)
	assert.Error(t, err)
	authErr, err = autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, "invalid \"display\" in request", authErr.Description)

	err = r.ValidateDisplay(false)
	assert.Error(t, err)
	authErr, err = autherrors.ToAuthLibError(err)
	assert.NoError(t, err)
	assert.Equal(t, "invalid \"display\" in request", authErr.Description)

	r.Display = attributes.DisplayTouch
	err = r.ValidateDisplay(true)
	assert.Nil(t, err)
}
