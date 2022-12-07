// Code generated by mockery v2.15.0. DO NOT EDIT.

package mocks

import (
	context "context"

	apiclient "github.com/argoproj/argo-cd/v2/reposerver/apiclient"

	grpc "google.golang.org/grpc"

	mock "github.com/stretchr/testify/mock"

	v1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
)

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

// GenerateManifestWithFiles provides a mock function with given fields: ctx, opts
func (_m *RepoServerServiceClient) GenerateManifestWithFiles(ctx context.Context, opts ...grpc.CallOption) (apiclient.RepoServerService_GenerateManifestWithFilesClient, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 apiclient.RepoServerService_GenerateManifestWithFilesClient
	if rf, ok := ret.Get(0).(func(context.Context, ...grpc.CallOption) apiclient.RepoServerService_GenerateManifestWithFilesClient); ok {
		r0 = rf(ctx, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(apiclient.RepoServerService_GenerateManifestWithFilesClient)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, opts...)
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

// GetHelmCharts provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetHelmCharts(ctx context.Context, in *apiclient.HelmChartsRequest, opts ...grpc.CallOption) (*apiclient.HelmChartsResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.HelmChartsResponse
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.HelmChartsRequest, ...grpc.CallOption) *apiclient.HelmChartsResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.HelmChartsResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.HelmChartsRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetRevisionChartDetails provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) GetRevisionChartDetails(ctx context.Context, in *apiclient.RepoServerRevisionChartDetailsRequest, opts ...grpc.CallOption) (*v1alpha1.ChartDetails, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *v1alpha1.ChartDetails
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.RepoServerRevisionChartDetailsRequest, ...grpc.CallOption) *v1alpha1.ChartDetails); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1alpha1.ChartDetails)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.RepoServerRevisionChartDetailsRequest, ...grpc.CallOption) error); ok {
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

// ListRefs provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) ListRefs(ctx context.Context, in *apiclient.ListRefsRequest, opts ...grpc.CallOption) (*apiclient.Refs, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.Refs
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.ListRefsRequest, ...grpc.CallOption) *apiclient.Refs); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.Refs)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.ListRefsRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ResolveRevision provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) ResolveRevision(ctx context.Context, in *apiclient.ResolveRevisionRequest, opts ...grpc.CallOption) (*apiclient.ResolveRevisionResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.ResolveRevisionResponse
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.ResolveRevisionRequest, ...grpc.CallOption) *apiclient.ResolveRevisionResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.ResolveRevisionResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.ResolveRevisionRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TestRepository provides a mock function with given fields: ctx, in, opts
func (_m *RepoServerServiceClient) TestRepository(ctx context.Context, in *apiclient.TestRepositoryRequest, opts ...grpc.CallOption) (*apiclient.TestRepositoryResponse, error) {
	_va := make([]interface{}, len(opts))
	for _i := range opts {
		_va[_i] = opts[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, in)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *apiclient.TestRepositoryResponse
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.TestRepositoryRequest, ...grpc.CallOption) *apiclient.TestRepositoryResponse); ok {
		r0 = rf(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*apiclient.TestRepositoryResponse)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *apiclient.TestRepositoryRequest, ...grpc.CallOption) error); ok {
		r1 = rf(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewRepoServerServiceClient interface {
	mock.TestingT
	Cleanup(func())
}

// NewRepoServerServiceClient creates a new instance of RepoServerServiceClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewRepoServerServiceClient(t mockConstructorTestingTNewRepoServerServiceClient) *RepoServerServiceClient {
	mock := &RepoServerServiceClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
