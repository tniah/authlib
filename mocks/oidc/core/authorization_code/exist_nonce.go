// Code generated by mockery v2.49.0. DO NOT EDIT.

package oidc

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
	requests "github.com/tniah/authlib/requests"
)

// MockExistNonce is an autogenerated mock type for the ExistNonce type
type MockExistNonce struct {
	mock.Mock
}

type MockExistNonce_Expecter struct {
	mock *mock.Mock
}

func (_m *MockExistNonce) EXPECT() *MockExistNonce_Expecter {
	return &MockExistNonce_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: ctx, nonce, r
func (_m *MockExistNonce) Execute(ctx context.Context, nonce string, r *requests.AuthorizationRequest) bool {
	ret := _m.Called(ctx, nonce, r)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string, *requests.AuthorizationRequest) bool); ok {
		r0 = rf(ctx, nonce, r)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// MockExistNonce_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockExistNonce_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - ctx context.Context
//   - nonce string
//   - r *requests.AuthorizationRequest
func (_e *MockExistNonce_Expecter) Execute(ctx interface{}, nonce interface{}, r interface{}) *MockExistNonce_Execute_Call {
	return &MockExistNonce_Execute_Call{Call: _e.mock.On("Execute", ctx, nonce, r)}
}

func (_c *MockExistNonce_Execute_Call) Run(run func(ctx context.Context, nonce string, r *requests.AuthorizationRequest)) *MockExistNonce_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(*requests.AuthorizationRequest))
	})
	return _c
}

func (_c *MockExistNonce_Execute_Call) Return(_a0 bool) *MockExistNonce_Execute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockExistNonce_Execute_Call) RunAndReturn(run func(context.Context, string, *requests.AuthorizationRequest) bool) *MockExistNonce_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockExistNonce creates a new instance of MockExistNonce. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockExistNonce(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockExistNonce {
	mock := &MockExistNonce{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
