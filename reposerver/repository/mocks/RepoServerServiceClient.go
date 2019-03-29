// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import context "context"
import grpc "google.golang.org/grpc"
import mock "github.com/stretchr/testify/mock"
import repository "github.com/argoproj/argo-cd/reposerver/repository"

// RepoServerServiceClient is an autogenerated mock type for the RepoServerServiceClient type
type RepoServerServiceClient struct {
	mock.Mock
}

// GenerateManifest provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GenerateManifest(ctx context.Context, in *repository.ManifestRequest, opts ...grpc.CallOption) (*repository.ManifestResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *repository.ManifestResponse
	if rf, ok := ret.Get(0).(func(context.Context, *repository.ManifestRequest, ...grpc.CallOption) *repository.ManifestResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.ManifestResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *repository.ManifestRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetApp provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetApp(ctx context.Context, in *repository.GetAppRequest, opts ...grpc.CallOption) (*repository.GetAppResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *repository.GetAppResponse
	if rf, ok := ret.Get(0).(func(context.Context, *repository.GetAppRequest, ...grpc.CallOption) *repository.GetAppResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.GetAppResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *repository.GetAppRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAppDetails provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetAppDetails(ctx context.Context, in *repository.RepoServerAppDetailsQuery, opts ...grpc.CallOption) (*repository.RepoAppDetailsResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *repository.RepoAppDetailsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *repository.RepoServerAppDetailsQuery, ...grpc.CallOption) *repository.RepoAppDetailsResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.RepoAppDetailsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *repository.RepoServerAppDetailsQuery, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListApps provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) ListApps(ctx context.Context, in *repository.ListAppsRequest, opts ...grpc.CallOption) (*repository.ListAppsResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *repository.ListAppsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *repository.ListAppsRequest, ...grpc.CallOption) *repository.ListAppsResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.ListAppsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *repository.ListAppsRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
