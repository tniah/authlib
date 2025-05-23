// Code generated by mockery v2.49.0. DO NOT EDIT.

package rfc6750

import (
	mock "github.com/stretchr/testify/mock"
	models "github.com/tniah/authlib/models"

	requests "github.com/tniah/authlib/requests"
)

// MockTokenGenerator is an autogenerated mock type for the TokenGenerator type
type MockTokenGenerator struct {
	mock.Mock
}

type MockTokenGenerator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockTokenGenerator) EXPECT() *MockTokenGenerator_Expecter {
	return &MockTokenGenerator_Expecter{mock: &_m.Mock}
}

// Generate provides a mock function with given fields: token, r
func (_m *MockTokenGenerator) Generate(token models.Token, r *requests.TokenRequest) error {
	ret := _m.Called(token, r)

	if len(ret) == 0 {
		panic("no return value specified for Generate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Token, *requests.TokenRequest) error); ok {
		r0 = rf(token, r)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockTokenGenerator_Generate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Generate'
type MockTokenGenerator_Generate_Call struct {
	*mock.Call
}

// Generate is a helper method to define mock.On call
//   - token models.Token
//   - r *requests.TokenRequest
func (_e *MockTokenGenerator_Expecter) Generate(token interface{}, r interface{}) *MockTokenGenerator_Generate_Call {
	return &MockTokenGenerator_Generate_Call{Call: _e.mock.On("Generate", token, r)}
}

func (_c *MockTokenGenerator_Generate_Call) Run(run func(token models.Token, r *requests.TokenRequest)) *MockTokenGenerator_Generate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Token), args[1].(*requests.TokenRequest))
	})
	return _c
}

func (_c *MockTokenGenerator_Generate_Call) Return(_a0 error) *MockTokenGenerator_Generate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockTokenGenerator_Generate_Call) RunAndReturn(run func(models.Token, *requests.TokenRequest) error) *MockTokenGenerator_Generate_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockTokenGenerator creates a new instance of MockTokenGenerator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockTokenGenerator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockTokenGenerator {
	mock := &MockTokenGenerator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
