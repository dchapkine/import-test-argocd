// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: server/cluster/cluster.proto

/*
	Package cluster is a generated protocol buffer package.

	Cluster Service

	Cluster Service API performs CRUD actions against cluster resources

	It is generated from these files:
		server/cluster/cluster.proto

	It has these top-level messages:
		ClusterQuery
		ClusterResponse
		ClusterCreateRequest
		ClusterUpdateRequest
*/
package cluster

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "google.golang.org/genproto/googleapis/api/annotations"
import _ "k8s.io/api/core/v1"
import github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// ClusterQuery is a query for cluster resources
type ClusterQuery struct {
	Server string `protobuf:"bytes,1,opt,name=server,proto3" json:"server,omitempty"`
}

func (m *ClusterQuery) Reset()                    { *m = ClusterQuery{} }
func (m *ClusterQuery) String() string            { return proto.CompactTextString(m) }
func (*ClusterQuery) ProtoMessage()               {}
func (*ClusterQuery) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{0} }

func (m *ClusterQuery) GetServer() string {
	if m != nil {
		return m.Server
	}
	return ""
}

type ClusterResponse struct {
}

func (m *ClusterResponse) Reset()                    { *m = ClusterResponse{} }
func (m *ClusterResponse) String() string            { return proto.CompactTextString(m) }
func (*ClusterResponse) ProtoMessage()               {}
func (*ClusterResponse) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{1} }

type ClusterCreateRequest struct {
	Cluster *github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster `protobuf:"bytes,1,opt,name=cluster" json:"cluster,omitempty"`
	Upsert  bool                                                               `protobuf:"varint,2,opt,name=upsert,proto3" json:"upsert,omitempty"`
}

func (m *ClusterCreateRequest) Reset()                    { *m = ClusterCreateRequest{} }
func (m *ClusterCreateRequest) String() string            { return proto.CompactTextString(m) }
func (*ClusterCreateRequest) ProtoMessage()               {}
func (*ClusterCreateRequest) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{2} }

func (m *ClusterCreateRequest) GetCluster() *github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster {
	if m != nil {
		return m.Cluster
	}
	return nil
}

func (m *ClusterCreateRequest) GetUpsert() bool {
	if m != nil {
		return m.Upsert
	}
	return false
}

type ClusterUpdateRequest struct {
	Cluster *github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster `protobuf:"bytes,1,opt,name=cluster" json:"cluster,omitempty"`
}

func (m *ClusterUpdateRequest) Reset()                    { *m = ClusterUpdateRequest{} }
func (m *ClusterUpdateRequest) String() string            { return proto.CompactTextString(m) }
func (*ClusterUpdateRequest) ProtoMessage()               {}
func (*ClusterUpdateRequest) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{3} }

func (m *ClusterUpdateRequest) GetCluster() *github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster {
	if m != nil {
		return m.Cluster
	}
	return nil
}

func init() {
	proto.RegisterType((*ClusterQuery)(nil), "cluster.ClusterQuery")
	proto.RegisterType((*ClusterResponse)(nil), "cluster.ClusterResponse")
	proto.RegisterType((*ClusterCreateRequest)(nil), "cluster.ClusterCreateRequest")
	proto.RegisterType((*ClusterUpdateRequest)(nil), "cluster.ClusterUpdateRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ClusterService service

type ClusterServiceClient interface {
	// List returns list of clusters
	List(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.ClusterList, error)
	// Create creates a cluster
	Create(ctx context.Context, in *ClusterCreateRequest, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Get returns a cluster by server address
	Get(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Update updates a cluster
	Update(ctx context.Context, in *ClusterUpdateRequest, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Delete deletes a cluster
	Delete(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error)
}

type clusterServiceClient struct {
	cc *grpc.ClientConn
}

func NewClusterServiceClient(cc *grpc.ClientConn) ClusterServiceClient {
	return &clusterServiceClient{cc}
}

func (c *clusterServiceClient) List(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.ClusterList, error) {
	out := new(github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.ClusterList)
	err := grpc.Invoke(ctx, "/cluster.ClusterService/List", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Create(ctx context.Context, in *ClusterCreateRequest, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error) {
	out := new(github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster)
	err := grpc.Invoke(ctx, "/cluster.ClusterService/Create", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Get(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error) {
	out := new(github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster)
	err := grpc.Invoke(ctx, "/cluster.ClusterService/Get", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Update(ctx context.Context, in *ClusterUpdateRequest, opts ...grpc.CallOption) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error) {
	out := new(github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster)
	err := grpc.Invoke(ctx, "/cluster.ClusterService/Update", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterServiceClient) Delete(ctx context.Context, in *ClusterQuery, opts ...grpc.CallOption) (*ClusterResponse, error) {
	out := new(ClusterResponse)
	err := grpc.Invoke(ctx, "/cluster.ClusterService/Delete", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for ClusterService service

type ClusterServiceServer interface {
	// List returns list of clusters
	List(context.Context, *ClusterQuery) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.ClusterList, error)
	// Create creates a cluster
	Create(context.Context, *ClusterCreateRequest) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Get returns a cluster by server address
	Get(context.Context, *ClusterQuery) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Update updates a cluster
	Update(context.Context, *ClusterUpdateRequest) (*github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster, error)
	// Delete deletes a cluster
	Delete(context.Context, *ClusterQuery) (*ClusterResponse, error)
}

func RegisterClusterServiceServer(s *grpc.Server, srv ClusterServiceServer) {
	s.RegisterService(&_ClusterService_serviceDesc, srv)
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
		FullMethod: "/cluster.ClusterService/List",
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
		FullMethod: "/cluster.ClusterService/Create",
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
		FullMethod: "/cluster.ClusterService/Get",
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
		FullMethod: "/cluster.ClusterService/Update",
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
		FullMethod: "/cluster.ClusterService/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterServiceServer).Delete(ctx, req.(*ClusterQuery))
	}
	return interceptor(ctx, in, info, handler)
}

var _ClusterService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cluster.ClusterService",
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
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "server/cluster/cluster.proto",
}

func (m *ClusterQuery) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterQuery) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Server) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCluster(dAtA, i, uint64(len(m.Server)))
		i += copy(dAtA[i:], m.Server)
	}
	return i, nil
}

func (m *ClusterResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterResponse) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	return i, nil
}

func (m *ClusterCreateRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterCreateRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Cluster != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCluster(dAtA, i, uint64(m.Cluster.Size()))
		n1, err := m.Cluster.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.Upsert {
		dAtA[i] = 0x10
		i++
		if m.Upsert {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	return i, nil
}

func (m *ClusterUpdateRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterUpdateRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Cluster != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCluster(dAtA, i, uint64(m.Cluster.Size()))
		n2, err := m.Cluster.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	return i, nil
}

func encodeVarintCluster(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *ClusterQuery) Size() (n int) {
	var l int
	_ = l
	l = len(m.Server)
	if l > 0 {
		n += 1 + l + sovCluster(uint64(l))
	}
	return n
}

func (m *ClusterResponse) Size() (n int) {
	var l int
	_ = l
	return n
}

func (m *ClusterCreateRequest) Size() (n int) {
	var l int
	_ = l
	if m.Cluster != nil {
		l = m.Cluster.Size()
		n += 1 + l + sovCluster(uint64(l))
	}
	if m.Upsert {
		n += 2
	}
	return n
}

func (m *ClusterUpdateRequest) Size() (n int) {
	var l int
	_ = l
	if m.Cluster != nil {
		l = m.Cluster.Size()
		n += 1 + l + sovCluster(uint64(l))
	}
	return n
}

func sovCluster(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozCluster(x uint64) (n int) {
	return sovCluster(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ClusterQuery) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterQuery: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterQuery: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Server", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Server = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCluster
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCluster
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterCreateRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterCreateRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterCreateRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Cluster", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Cluster == nil {
				m.Cluster = &github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster{}
			}
			if err := m.Cluster.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Upsert", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Upsert = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCluster
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ClusterUpdateRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterUpdateRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterUpdateRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Cluster", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Cluster == nil {
				m.Cluster = &github_com_argoproj_argo_cd_pkg_apis_application_v1alpha1.Cluster{}
			}
			if err := m.Cluster.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthCluster
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipCluster(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthCluster
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowCluster
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipCluster(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthCluster = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCluster   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("server/cluster/cluster.proto", fileDescriptorCluster) }

var fileDescriptorCluster = []byte{
	// 472 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x94, 0xcf, 0x8b, 0x13, 0x31,
	0x14, 0xc7, 0xc9, 0xaa, 0xa3, 0x46, 0xf1, 0x47, 0x58, 0xa5, 0x8e, 0x6b, 0xd9, 0xcd, 0x41, 0x96,
	0x45, 0x13, 0x5a, 0x2f, 0x8b, 0xc7, 0x5d, 0x51, 0x04, 0x2f, 0x56, 0xbc, 0xc8, 0x82, 0x64, 0xa7,
	0x8f, 0xec, 0xd8, 0x71, 0x12, 0x93, 0xcc, 0x80, 0x88, 0x08, 0x7a, 0x15, 0x2f, 0xfe, 0x01, 0x5e,
	0xfd, 0x53, 0x3c, 0x0a, 0xfe, 0x03, 0x52, 0xfc, 0x43, 0x64, 0x32, 0x49, 0xbb, 0x6d, 0xa9, 0x17,
	0xcb, 0x9e, 0x9a, 0xbc, 0xa4, 0xef, 0x7d, 0xf2, 0x7d, 0xdf, 0x79, 0x78, 0xc3, 0x82, 0xa9, 0xc1,
	0xf0, 0xac, 0xa8, 0xac, 0x9b, 0xfe, 0x32, 0x6d, 0x94, 0x53, 0xe4, 0x6c, 0xd8, 0xa6, 0xeb, 0x52,
	0x49, 0xe5, 0x63, 0xbc, 0x59, 0xb5, 0xc7, 0xe9, 0x86, 0x54, 0x4a, 0x16, 0xc0, 0x85, 0xce, 0xb9,
	0x28, 0x4b, 0xe5, 0x84, 0xcb, 0x55, 0x69, 0xc3, 0x29, 0x1d, 0xed, 0x5a, 0x96, 0x2b, 0x7f, 0x9a,
	0x29, 0x03, 0xbc, 0xee, 0x71, 0x09, 0x25, 0x18, 0xe1, 0x60, 0x18, 0xee, 0x3c, 0x96, 0xb9, 0x3b,
	0xaa, 0x0e, 0x59, 0xa6, 0x5e, 0x73, 0x61, 0x7c, 0x89, 0x57, 0x7e, 0x71, 0x37, 0x1b, 0x72, 0x3d,
	0x92, 0xcd, 0x9f, 0x2d, 0x17, 0x5a, 0x17, 0x79, 0xe6, 0x93, 0xf3, 0xba, 0x27, 0x0a, 0x7d, 0x24,
	0x16, 0x52, 0xd1, 0xdb, 0xf8, 0xe2, 0x7e, 0x4b, 0xfb, 0xb4, 0x02, 0xf3, 0x96, 0x5c, 0xc7, 0x49,
	0xfb, 0xb6, 0x0e, 0xda, 0x44, 0xdb, 0xe7, 0x07, 0x61, 0x47, 0xaf, 0xe2, 0xcb, 0xe1, 0xde, 0x00,
	0xac, 0x56, 0xa5, 0x05, 0xfa, 0x19, 0xe1, 0xf5, 0x10, 0xdb, 0x37, 0x20, 0x1c, 0x0c, 0xe0, 0x4d,
	0x05, 0xd6, 0x91, 0x03, 0x1c, 0x15, 0xf0, 0x49, 0x2e, 0xf4, 0xf7, 0xd8, 0x14, 0x98, 0x45, 0x60,
	0xbf, 0x78, 0x99, 0x0d, 0x99, 0x1e, 0x49, 0xd6, 0x00, 0xb3, 0x63, 0xc0, 0x2c, 0x02, 0xb3, 0x58,
	0x35, 0xa6, 0x6c, 0x08, 0x2b, 0x6d, 0xc1, 0xb8, 0xce, 0xda, 0x26, 0xda, 0x3e, 0x37, 0x08, 0x3b,
	0xea, 0x26, 0x34, 0xcf, 0xf5, 0xf0, 0xa4, 0x68, 0xfa, 0xdf, 0xcf, 0xe0, 0x4b, 0x21, 0xf8, 0x0c,
	0x4c, 0x9d, 0x67, 0x40, 0x3e, 0xe0, 0xd3, 0x4f, 0x72, 0xeb, 0xc8, 0x35, 0x16, 0x6d, 0x71, 0x5c,
	0xe1, 0xf4, 0xe1, 0xff, 0x97, 0x6f, 0xd2, 0xd3, 0xce, 0xc7, 0x5f, 0x7f, 0xbe, 0xae, 0x11, 0x72,
	0xc5, 0x5b, 0xa5, 0xee, 0x45, 0x13, 0x5a, 0xf2, 0x05, 0xe1, 0xa4, 0xed, 0x08, 0xb9, 0x35, 0xcf,
	0x30, 0xd3, 0xa9, 0x74, 0x05, 0x52, 0xd0, 0x2d, 0xcf, 0x71, 0x93, 0x2e, 0x70, 0xdc, 0x9f, 0xb4,
	0xec, 0x13, 0xc2, 0xa7, 0x1e, 0xc1, 0x52, 0x45, 0x56, 0x48, 0x41, 0x6e, 0xcc, 0x53, 0xf0, 0x77,
	0xad, 0x83, 0xdf, 0x93, 0x6f, 0x08, 0x27, 0xad, 0x35, 0x16, 0x65, 0x99, 0xb1, 0xcc, 0x4a, 0x80,
	0xfa, 0x1e, 0xe8, 0x4e, 0xba, 0xb5, 0x08, 0x14, 0x6b, 0x07, 0xb0, 0xa9, 0x4e, 0x07, 0x38, 0x79,
	0x00, 0x05, 0x38, 0x58, 0xa6, 0x54, 0x67, 0x3e, 0x3c, 0xf9, 0x18, 0xc3, 0xfb, 0x77, 0x96, 0xbf,
	0x7f, 0x6f, 0xf7, 0xc7, 0xb8, 0x8b, 0x7e, 0x8e, 0xbb, 0xe8, 0xf7, 0xb8, 0x8b, 0x5e, 0xec, 0xfc,
	0x6b, 0x86, 0xcc, 0x8e, 0xb7, 0xc3, 0xc4, 0xcf, 0x8a, 0x7b, 0x7f, 0x03, 0x00, 0x00, 0xff, 0xff,
	0x2c, 0xae, 0x46, 0x1e, 0xf7, 0x04, 0x00, 0x00,
}
