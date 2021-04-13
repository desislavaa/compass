// Code generated by mockery v2.5.1. DO NOT EDIT.

package automock

import (
	admin "github.com/ory/hydra-client-go/client/admin"
	mock "github.com/stretchr/testify/mock"
)

// OryHydraService is an autogenerated mock type for the OryHydraService type
type OryHydraService struct {
	mock.Mock
}

// CreateOAuth2Client provides a mock function with given fields: params
func (_m *OryHydraService) CreateOAuth2Client(params *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
	ret := _m.Called(params)

	var r0 *admin.CreateOAuth2ClientCreated
	if rf, ok := ret.Get(0).(func(*admin.CreateOAuth2ClientParams) *admin.CreateOAuth2ClientCreated); ok {
		r0 = rf(params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.CreateOAuth2ClientCreated)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.CreateOAuth2ClientParams) error); ok {
		r1 = rf(params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteOAuth2Client provides a mock function with given fields: params
func (_m *OryHydraService) DeleteOAuth2Client(params *admin.DeleteOAuth2ClientParams) (*admin.DeleteOAuth2ClientNoContent, error) {
	ret := _m.Called(params)

	var r0 *admin.DeleteOAuth2ClientNoContent
	if rf, ok := ret.Get(0).(func(*admin.DeleteOAuth2ClientParams) *admin.DeleteOAuth2ClientNoContent); ok {
		r0 = rf(params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.DeleteOAuth2ClientNoContent)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.DeleteOAuth2ClientParams) error); ok {
		r1 = rf(params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListOAuth2Clients provides a mock function with given fields: params
func (_m *OryHydraService) ListOAuth2Clients(params *admin.ListOAuth2ClientsParams) (*admin.ListOAuth2ClientsOK, error) {
	ret := _m.Called(params)

	var r0 *admin.ListOAuth2ClientsOK
	if rf, ok := ret.Get(0).(func(*admin.ListOAuth2ClientsParams) *admin.ListOAuth2ClientsOK); ok {
		r0 = rf(params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.ListOAuth2ClientsOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.ListOAuth2ClientsParams) error); ok {
		r1 = rf(params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateOAuth2Client provides a mock function with given fields: params
func (_m *OryHydraService) UpdateOAuth2Client(params *admin.UpdateOAuth2ClientParams) (*admin.UpdateOAuth2ClientOK, error) {
	ret := _m.Called(params)

	var r0 *admin.UpdateOAuth2ClientOK
	if rf, ok := ret.Get(0).(func(*admin.UpdateOAuth2ClientParams) *admin.UpdateOAuth2ClientOK); ok {
		r0 = rf(params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*admin.UpdateOAuth2ClientOK)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*admin.UpdateOAuth2ClientParams) error); ok {
		r1 = rf(params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
