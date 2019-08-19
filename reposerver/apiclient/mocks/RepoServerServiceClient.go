// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import apiclient "github.com/argoproj/argo-cd/reposerver/apiclient"
import context "context"
import grpc "google.golang.org/grpc"
import mock "github.com/stretchr/testify/mock"
import v1alpha1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"

// RepoServerServiceClient is an autogenerated mock type for the RepoServerServiceClient type
type RepoServerServiceClient struct {
	mock.Mock
}

// GenerateManifest provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GenerateManifest(ctx context.Context, in *apiclient.ManifestRequest, opts ...grpc.CallOption) (*apiclient.ManifestResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.ManifestResponse
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.ManifestRequest, ...grpc.CallOption) *apiclient.ManifestResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.ManifestResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.ManifestRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAppDetails provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetAppDetails(ctx context.Context, in *apiclient.RepoServerAppDetailsQuery, opts ...grpc.CallOption) (*apiclient.RepoAppDetailsResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.RepoAppDetailsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.RepoServerAppDetailsQuery, ...grpc.CallOption) *apiclient.RepoAppDetailsResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.RepoAppDetailsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.RepoServerAppDetailsQuery, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRevisionMetadata provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetRevisionMetadata(ctx context.Context, in *apiclient.RepoServerRevisionMetadataRequest, opts ...grpc.CallOption) (*v1alpha1.RevisionMetadata, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *v1alpha1.RevisionMetadata
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.RepoServerRevisionMetadataRequest, ...grpc.CallOption) *v1alpha1.RevisionMetadata); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1alpha1.RevisionMetadata)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.RepoServerRevisionMetadataRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListApps provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) ListApps(ctx context.Context, in *apiclient.ListAppsRequest, opts ...grpc.CallOption) (*apiclient.AppList, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.AppList
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.ListAppsRequest, ...grpc.CallOption) *apiclient.AppList); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.AppList)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.ListAppsRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
