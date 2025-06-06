// Code generated by mockery v2.49.0. DO NOT EDIT.

package oidc

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
	models "github.com/tniah/authlib/models"
)

// MockIssuerGenerator is an autogenerated mock type for the IssuerGenerator type
type MockIssuerGenerator struct {
	mock.Mock
}

type MockIssuerGenerator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockIssuerGenerator) EXPECT() *MockIssuerGenerator_Expecter {
	return &MockIssuerGenerator_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: ctx, client
func (_m *MockIssuerGenerator) Execute(ctx context.Context, client models.Client) string {
	ret := _m.Called(ctx, client)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, models.Client) string); ok {
		r0 = rf(ctx, client)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockIssuerGenerator_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockIssuerGenerator_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - ctx context.Context
//   - client models.Client
func (_e *MockIssuerGenerator_Expecter) Execute(ctx interface{}, client interface{}) *MockIssuerGenerator_Execute_Call {
	return &MockIssuerGenerator_Execute_Call{Call: _e.mock.On("Execute", ctx, client)}
}

func (_c *MockIssuerGenerator_Execute_Call) Run(run func(ctx context.Context, client models.Client)) *MockIssuerGenerator_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(models.Client))
	})
	return _c
}

func (_c *MockIssuerGenerator_Execute_Call) Return(_a0 string) *MockIssuerGenerator_Execute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockIssuerGenerator_Execute_Call) RunAndReturn(run func(context.Context, models.Client) string) *MockIssuerGenerator_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockIssuerGenerator creates a new instance of MockIssuerGenerator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockIssuerGenerator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockIssuerGenerator {
	mock := &MockIssuerGenerator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
