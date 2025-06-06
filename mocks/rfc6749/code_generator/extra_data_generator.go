// Code generated by mockery v2.49.0. DO NOT EDIT.

package codegen

import (
	mock "github.com/stretchr/testify/mock"
	requests "github.com/tniah/authlib/requests"
)

// MockExtraDataGenerator is an autogenerated mock type for the ExtraDataGenerator type
type MockExtraDataGenerator struct {
	mock.Mock
}

type MockExtraDataGenerator_Expecter struct {
	mock *mock.Mock
}

func (_m *MockExtraDataGenerator) EXPECT() *MockExtraDataGenerator_Expecter {
	return &MockExtraDataGenerator_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: r
func (_m *MockExtraDataGenerator) Execute(r *requests.AuthorizationRequest) (map[string]interface{}, error) {
	ret := _m.Called(r)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 map[string]interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(*requests.AuthorizationRequest) (map[string]interface{}, error)); ok {
		return rf(r)
	}
	if rf, ok := ret.Get(0).(func(*requests.AuthorizationRequest) map[string]interface{}); ok {
		r0 = rf(r)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(*requests.AuthorizationRequest) error); ok {
		r1 = rf(r)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockExtraDataGenerator_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockExtraDataGenerator_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - r *requests.AuthorizationRequest
func (_e *MockExtraDataGenerator_Expecter) Execute(r interface{}) *MockExtraDataGenerator_Execute_Call {
	return &MockExtraDataGenerator_Execute_Call{Call: _e.mock.On("Execute", r)}
}

func (_c *MockExtraDataGenerator_Execute_Call) Run(run func(r *requests.AuthorizationRequest)) *MockExtraDataGenerator_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*requests.AuthorizationRequest))
	})
	return _c
}

func (_c *MockExtraDataGenerator_Execute_Call) Return(_a0 map[string]interface{}, _a1 error) *MockExtraDataGenerator_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockExtraDataGenerator_Execute_Call) RunAndReturn(run func(*requests.AuthorizationRequest) (map[string]interface{}, error)) *MockExtraDataGenerator_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockExtraDataGenerator creates a new instance of MockExtraDataGenerator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockExtraDataGenerator(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockExtraDataGenerator {
	mock := &MockExtraDataGenerator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
