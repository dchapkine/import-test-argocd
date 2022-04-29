// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             (unknown)
// source: apiclient/cluster/cluster.proto

package cluster

import (
	context "context"
	v1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ClusterServiceClient is the client API for ClusterService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ClusterServiceClient interface {
	// List returns list of clusters
	List(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.ClusterList, error)
	// Create creates a cluster
	Create(ctx context.Context, in *ClusterCreateRequest, opts ...grpc.CallOption) (*v1alpha1.Cluster, error)
	// Get returns a cluster by server address
	Get(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.Cluster, error)
	// Update updates a cluster
	Update(ctx context.Context, in *ClusterUpdateRequest, opts ...grpc.CallOption) (*v1alpha1.Cluster, error)
	// Delete deletes a cluster
	Delete(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error)
	// RotateAuth rotates the bearer token used for a cluster
	RotateAuth(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error)
	// InvalidateCache invalidates cluster cache
	InvalidateCache(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.Cluster, error)
}

type clusterServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewClusterServiceClient(cc grpc.ClientConnInterface) ClusterServiceClient {
	return &clusterServiceClient{cc}
}

func (c *clusterServiceClient) List(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.ClusterList, error) {
	out := new(v1alpha1.ClusterList)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Create(ctx context.Context, in *ClusterCreateRequest, opts ...grpc.CallOption) (*v1alpha1.Cluster, error) {
	out := new(v1alpha1.Cluster)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Get(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.Cluster, error) {
	out := new(v1alpha1.Cluster)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Update(ctx context.Context, in *ClusterUpdateRequest, opts ...grpc.CallOption) (*v1alpha1.Cluster, error) {
	out := new(v1alpha1.Cluster)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/Update", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Delete(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error) {
	out := new(ClusterResponse)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) RotateAuth(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error) {
	out := new(ClusterResponse)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/RotateAuth", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) InvalidateCache(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*v1alpha1.Cluster, error) {
	out := new(v1alpha1.Cluster)
	err := c.cc.Invoke(ctx, "/apiclient.cluster.ClusterService/InvalidateCache", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClusterServiceServer is the server API for ClusterService service.
// All implementations must embed UnimplementedClusterServiceServer
// for forward compatibility
type ClusterServiceServer interface {
	// List returns list of clusters
	List(context.Context, *ClusterQuery) (*v1alpha1.ClusterList, error)
	// Create creates a cluster
	Create(context.Context, *ClusterCreateRequest) (*v1alpha1.Cluster, error)
	// Get returns a cluster by server address
	Get(context.Context, *ClusterQuery) (*v1alpha1.Cluster, error)
	// Update updates a cluster
	Update(context.Context, *ClusterUpdateRequest) (*v1alpha1.Cluster, error)
	// Delete deletes a cluster
	Delete(context.Context, *ClusterQuery) (*ClusterResponse, error)
	// RotateAuth rotates the bearer token used for a cluster
	RotateAuth(context.Context, *ClusterQuery) (*ClusterResponse, error)
	// InvalidateCache invalidates cluster cache
	InvalidateCache(context.Context, *ClusterQuery) (*v1alpha1.Cluster, error)
	mustEmbedUnimplementedClusterServiceServer()
}

// UnimplementedClusterServiceServer must be embedded to have forward compatible implementations.
type UnimplementedClusterServiceServer struct {
}

func (UnimplementedClusterServiceServer) List(context.Context, *ClusterQuery) (*v1alpha1.ClusterList, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedClusterServiceServer) Create(context.Context, *ClusterCreateRequest) (*v1alpha1.Cluster, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}
func (UnimplementedClusterServiceServer) Get(context.Context, *ClusterQuery) (*v1alpha1.Cluster, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedClusterServiceServer) Update(context.Context, *ClusterUpdateRequest) (*v1alpha1.Cluster, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
func (UnimplementedClusterServiceServer) Delete(context.Context, *ClusterQuery) (*ClusterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Delete not implemented")
}
func (UnimplementedClusterServiceServer) RotateAuth(context.Context, *ClusterQuery) (*ClusterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RotateAuth not implemented")
}
func (UnimplementedClusterServiceServer) InvalidateCache(context.Context, *ClusterQuery) (*v1alpha1.Cluster, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InvalidateCache not implemented")
}
func (UnimplementedClusterServiceServer) mustEmbedUnimplementedClusterServiceServer() {}

// UnsafeClusterServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ClusterServiceServer will
// result in compilation errors.
type UnsafeClusterServiceServer interface {
	mustEmbedUnimplementedClusterServiceServer()
}

func RegisterClusterServiceServer(s grpc.ServiceRegistrar, srv ClusterServiceServer) {
	s.RegisterService(&ClusterService_ServiceDesc, srv)
}

func _ClusterService_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).List(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterCreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).Create(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).Create(ctx, req.(*ClusterCreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).Get(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_Update_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterUpdateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).Update(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/Update",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).Update(ctx, req.(*ClusterUpdateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).Delete(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_RotateAuth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).RotateAuth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/RotateAuth",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).RotateAuth(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterService_InvalidateCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClusterQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterServiceServer).InvalidateCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/apiclient.cluster.ClusterService/InvalidateCache",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).InvalidateCache(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

// ClusterService_ServiceDesc is the grpc.ServiceDesc for ClusterService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ClusterService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "apiclient.cluster.ClusterService",
	HandlerType: (*ClusterServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "List",
			Handler:    _ClusterService_List_Handler,
		},
		{
			MethodName: "Create",
			Handler:    _ClusterService_Create_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _ClusterService_Get_Handler,
		},
		{
			MethodName: "Update",
			Handler:    _ClusterService_Update_Handler,
		},
		{
			MethodName: "Delete",
			Handler:    _ClusterService_Delete_Handler,
		},
		{
			MethodName: "RotateAuth",
			Handler:    _ClusterService_RotateAuth_Handler,
		},
		{
			MethodName: "InvalidateCache",
			Handler:    _ClusterService_InvalidateCache_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "apiclient/cluster/cluster.proto",
}
