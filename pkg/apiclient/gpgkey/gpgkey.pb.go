// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: apiclient/gpgkey/gpgkey.proto

// GPG public key service
//
// GPG public key API performs CRUD actions against GnuPGPublicKey resources

package gpgkey

import (
	fmt "fmt"
	v1alpha1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	proto "github.com/gogo/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Message to query the server for configured GPG public keys
type GnuPGPublicKeyQuery struct {
	// The GPG key ID to query for
	KeyID                string   `protobuf:"bytes,1,opt,name=keyID,proto3" json:"keyID,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GnuPGPublicKeyQuery) Reset()         { *m = GnuPGPublicKeyQuery{} }
func (m *GnuPGPublicKeyQuery) String() string { return proto.CompactTextString(m) }
func (*GnuPGPublicKeyQuery) ProtoMessage()    {}
func (*GnuPGPublicKeyQuery) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fb0e67a53c44268, []int{0}
}
func (m *GnuPGPublicKeyQuery) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GnuPGPublicKeyQuery) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GnuPGPublicKeyQuery.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GnuPGPublicKeyQuery) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GnuPGPublicKeyQuery.Merge(m, src)
}
func (m *GnuPGPublicKeyQuery) XXX_Size() int {
	return m.Size()
}
func (m *GnuPGPublicKeyQuery) XXX_DiscardUnknown() {
	xxx_messageInfo_GnuPGPublicKeyQuery.DiscardUnknown(m)
}

var xxx_messageInfo_GnuPGPublicKeyQuery proto.InternalMessageInfo

func (m *GnuPGPublicKeyQuery) GetKeyID() string {
	if m != nil {
		return m.KeyID
	}
	return ""
}

// Request to create one or more public keys on the server
type GnuPGPublicKeyCreateRequest struct {
	// Raw key data of the GPG key(s) to create
	Publickey *v1alpha1.GnuPGPublicKey `protobuf:"bytes,1,opt,name=publickey,proto3" json:"publickey,omitempty"`
	// Whether to upsert already existing public keys
	Upsert               bool     `protobuf:"varint,2,opt,name=upsert,proto3" json:"upsert,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GnuPGPublicKeyCreateRequest) Reset()         { *m = GnuPGPublicKeyCreateRequest{} }
func (m *GnuPGPublicKeyCreateRequest) String() string { return proto.CompactTextString(m) }
func (*GnuPGPublicKeyCreateRequest) ProtoMessage()    {}
func (*GnuPGPublicKeyCreateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fb0e67a53c44268, []int{1}
}
func (m *GnuPGPublicKeyCreateRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GnuPGPublicKeyCreateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GnuPGPublicKeyCreateRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GnuPGPublicKeyCreateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GnuPGPublicKeyCreateRequest.Merge(m, src)
}
func (m *GnuPGPublicKeyCreateRequest) XXX_Size() int {
	return m.Size()
}
func (m *GnuPGPublicKeyCreateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GnuPGPublicKeyCreateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GnuPGPublicKeyCreateRequest proto.InternalMessageInfo

func (m *GnuPGPublicKeyCreateRequest) GetPublickey() *v1alpha1.GnuPGPublicKey {
	if m != nil {
		return m.Publickey
	}
	return nil
}

func (m *GnuPGPublicKeyCreateRequest) GetUpsert() bool {
	if m != nil {
		return m.Upsert
	}
	return false
}

// Response to a public key creation request
type GnuPGPublicKeyCreateResponse struct {
	// List of GPG public keys that have been created
	Created *v1alpha1.GnuPGPublicKeyList `protobuf:"bytes,1,opt,name=created,proto3" json:"created,omitempty"`
	// List of key IDs that haven been skipped because they already exist on the server
	Skipped              []string `protobuf:"bytes,2,rep,name=skipped,proto3" json:"skipped,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GnuPGPublicKeyCreateResponse) Reset()         { *m = GnuPGPublicKeyCreateResponse{} }
func (m *GnuPGPublicKeyCreateResponse) String() string { return proto.CompactTextString(m) }
func (*GnuPGPublicKeyCreateResponse) ProtoMessage()    {}
func (*GnuPGPublicKeyCreateResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fb0e67a53c44268, []int{2}
}
func (m *GnuPGPublicKeyCreateResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GnuPGPublicKeyCreateResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GnuPGPublicKeyCreateResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GnuPGPublicKeyCreateResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GnuPGPublicKeyCreateResponse.Merge(m, src)
}
func (m *GnuPGPublicKeyCreateResponse) XXX_Size() int {
	return m.Size()
}
func (m *GnuPGPublicKeyCreateResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GnuPGPublicKeyCreateResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GnuPGPublicKeyCreateResponse proto.InternalMessageInfo

func (m *GnuPGPublicKeyCreateResponse) GetCreated() *v1alpha1.GnuPGPublicKeyList {
	if m != nil {
		return m.Created
	}
	return nil
}

func (m *GnuPGPublicKeyCreateResponse) GetSkipped() []string {
	if m != nil {
		return m.Skipped
	}
	return nil
}

// Generic (empty) response for GPG public key CRUD requests
type GnuPGPublicKeyResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GnuPGPublicKeyResponse) Reset()         { *m = GnuPGPublicKeyResponse{} }
func (m *GnuPGPublicKeyResponse) String() string { return proto.CompactTextString(m) }
func (*GnuPGPublicKeyResponse) ProtoMessage()    {}
func (*GnuPGPublicKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fb0e67a53c44268, []int{3}
}
func (m *GnuPGPublicKeyResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GnuPGPublicKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GnuPGPublicKeyResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GnuPGPublicKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GnuPGPublicKeyResponse.Merge(m, src)
}
func (m *GnuPGPublicKeyResponse) XXX_Size() int {
	return m.Size()
}
func (m *GnuPGPublicKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GnuPGPublicKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GnuPGPublicKeyResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*GnuPGPublicKeyQuery)(nil), "apiclient.gpgkey.GnuPGPublicKeyQuery")
	proto.RegisterType((*GnuPGPublicKeyCreateRequest)(nil), "apiclient.gpgkey.GnuPGPublicKeyCreateRequest")
	proto.RegisterType((*GnuPGPublicKeyCreateResponse)(nil), "apiclient.gpgkey.GnuPGPublicKeyCreateResponse")
	proto.RegisterType((*GnuPGPublicKeyResponse)(nil), "apiclient.gpgkey.GnuPGPublicKeyResponse")
}

func init() { proto.RegisterFile("apiclient/gpgkey/gpgkey.proto", fileDescriptor_3fb0e67a53c44268) }

var fileDescriptor_3fb0e67a53c44268 = []byte{
	// 531 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0x4f, 0x8b, 0xd3, 0x4e,
	0x18, 0x26, 0xe9, 0xfe, 0xba, 0xbf, 0xce, 0x22, 0xee, 0x8e, 0xcb, 0x6e, 0xad, 0xb5, 0x96, 0x80,
	0xd0, 0x55, 0x9a, 0xa1, 0xdd, 0x5b, 0x6f, 0x5b, 0x17, 0x06, 0x59, 0x85, 0x18, 0x2f, 0x22, 0x7b,
	0x99, 0xa6, 0x2f, 0xd9, 0xb1, 0xd9, 0xcc, 0x98, 0x4c, 0x8a, 0x41, 0x14, 0xdc, 0xab, 0x47, 0xbf,
	0x81, 0x47, 0xbf, 0x87, 0x20, 0x9e, 0x04, 0xbf, 0x80, 0x14, 0x4f, 0x7e, 0x0a, 0xe9, 0x24, 0xad,
	0x6d, 0x5c, 0xd8, 0x78, 0x9a, 0xbc, 0xff, 0x9e, 0xe7, 0xc9, 0xfb, 0xbe, 0x33, 0xe8, 0x36, 0x93,
	0xdc, 0x0b, 0x38, 0x84, 0x8a, 0xf8, 0xd2, 0x9f, 0x40, 0x9a, 0x1f, 0xb6, 0x8c, 0x84, 0x12, 0x78,
	0x7b, 0x19, 0xb6, 0x33, 0x7f, 0xe3, 0x80, 0x49, 0x1e, 0x13, 0x26, 0x65, 0xc0, 0x3d, 0xa6, 0xb8,
	0x08, 0xc9, 0xb4, 0xc7, 0x02, 0x79, 0xc6, 0x7a, 0xc4, 0x87, 0x10, 0x22, 0xa6, 0x60, 0x9c, 0x15,
	0x37, 0x9a, 0xbe, 0x10, 0x7e, 0x00, 0x84, 0x49, 0x4e, 0x58, 0x18, 0x0a, 0xa5, 0xf3, 0xe3, 0x2c,
	0x6a, 0xdd, 0x47, 0x37, 0x68, 0x98, 0x38, 0xd4, 0x49, 0x46, 0x01, 0xf7, 0x4e, 0x20, 0x7d, 0x92,
	0x40, 0x94, 0xe2, 0x5d, 0xf4, 0xdf, 0x04, 0xd2, 0x87, 0xc7, 0x75, 0xa3, 0x6d, 0x74, 0x6a, 0x6e,
	0x66, 0x58, 0x6f, 0xd1, 0xad, 0xf5, 0xe4, 0x07, 0x11, 0x30, 0x05, 0x2e, 0xbc, 0x4c, 0x20, 0x56,
	0x98, 0xa2, 0x9a, 0xd4, 0x91, 0x09, 0xa4, 0xba, 0x70, 0xab, 0x7f, 0x60, 0xcf, 0x85, 0xda, 0x2b,
	0x42, 0xed, 0x85, 0x50, 0x7b, 0x1d, 0xca, 0xfd, 0x53, 0x8b, 0xf7, 0x50, 0x35, 0x91, 0x31, 0x44,
	0xaa, 0x6e, 0xb6, 0x8d, 0xce, 0xff, 0x6e, 0x6e, 0x59, 0xef, 0x0c, 0xd4, 0xbc, 0x5c, 0x40, 0x2c,
	0x45, 0x18, 0x03, 0xa6, 0x68, 0xd3, 0xd3, 0x9e, 0x71, 0xce, 0xdf, 0x2d, 0xcd, 0xff, 0x88, 0xc7,
	0xca, 0x5d, 0x54, 0xe3, 0x3a, 0xda, 0x8c, 0x27, 0x5c, 0x4a, 0x18, 0xd7, 0xcd, 0x76, 0xa5, 0x53,
	0x73, 0x17, 0xa6, 0x55, 0x47, 0x7b, 0x05, 0xe1, 0x39, 0x79, 0xff, 0x62, 0x03, 0x5d, 0xa3, 0x0e,
	0x3d, 0x81, 0xf4, 0x29, 0x44, 0x53, 0xee, 0x01, 0x4e, 0xd0, 0xc6, 0x1c, 0x16, 0xdf, 0xb5, 0x8b,
	0x03, 0xb4, 0x2f, 0x69, 0x7a, 0xe3, 0xdf, 0xc4, 0x5a, 0xfb, 0x17, 0xdf, 0x7f, 0x7e, 0x30, 0x77,
	0xf0, 0x75, 0x3d, 0xda, 0x69, 0x2f, 0xdf, 0x99, 0x18, 0xbf, 0x42, 0x15, 0x0a, 0xa5, 0x59, 0xcb,
	0x8f, 0xc8, 0xba, 0xa3, 0x19, 0x6f, 0xe2, 0xfd, 0x02, 0x23, 0x79, 0xad, 0xf7, 0xe3, 0x0d, 0x7e,
	0x6f, 0xa0, 0x6a, 0x36, 0x12, 0xdc, 0xbd, 0x8a, 0x7d, 0x6d, 0x77, 0x1a, 0x76, 0xd9, 0xf4, 0xac,
	0xd9, 0x96, 0xa5, 0xa5, 0x34, 0xad, 0xe2, 0xcf, 0x0f, 0x56, 0xd6, 0x28, 0x42, 0xd5, 0x63, 0x08,
	0x40, 0x41, 0xd9, 0x56, 0x74, 0xae, 0x4a, 0x5b, 0xd2, 0xe7, 0xbd, 0xbf, 0x57, 0xa4, 0x1f, 0x7e,
	0x36, 0xbe, 0xcc, 0x5a, 0xc6, 0xb7, 0x59, 0xcb, 0xf8, 0x31, 0x6b, 0x19, 0x68, 0xd7, 0x13, 0xe7,
	0x7f, 0x81, 0x0e, 0xb7, 0xa8, 0x3e, 0x9d, 0xf9, 0x0d, 0x74, 0x8c, 0xe7, 0x87, 0x3e, 0x57, 0x67,
	0xc9, 0xc8, 0xf6, 0xc4, 0x39, 0x61, 0x91, 0x2f, 0x64, 0x24, 0x5e, 0xe8, 0x8f, 0xae, 0x37, 0x26,
	0xd3, 0x3e, 0x91, 0x13, 0x9f, 0x14, 0x1f, 0x88, 0x8f, 0x66, 0xe5, 0x88, 0x3e, 0xfb, 0x64, 0x6e,
	0x1f, 0x2d, 0xc1, 0x33, 0xd0, 0xaf, 0x2b, 0xae, 0xd3, 0xcc, 0x35, 0x33, 0x9b, 0x45, 0xd7, 0x29,
	0x75, 0x86, 0x8f, 0x41, 0xb1, 0x31, 0x53, 0xec, 0x97, 0xb9, 0xb3, 0x0c, 0x0f, 0x06, 0x59, 0x7c,
	0x54, 0xd5, 0xcf, 0xc3, 0xe1, 0xef, 0x00, 0x00, 0x00, 0xff, 0xff, 0x57, 0x33, 0xa7, 0x7d, 0x9a,
	0x04, 0x00, 0x00,
}

func (m *GnuPGPublicKeyQuery) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GnuPGPublicKeyQuery) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GnuPGPublicKeyQuery) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.KeyID) > 0 {
		i -= len(m.KeyID)
		copy(dAtA[i:], m.KeyID)
		i = encodeVarintGpgkey(dAtA, i, uint64(len(m.KeyID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *GnuPGPublicKeyCreateRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GnuPGPublicKeyCreateRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GnuPGPublicKeyCreateRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Upsert {
		i--
		if m.Upsert {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if m.Publickey != nil {
		{
			size, err := m.Publickey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintGpgkey(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *GnuPGPublicKeyCreateResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GnuPGPublicKeyCreateResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GnuPGPublicKeyCreateResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Skipped) > 0 {
		for iNdEx := len(m.Skipped) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Skipped[iNdEx])
			copy(dAtA[i:], m.Skipped[iNdEx])
			i = encodeVarintGpgkey(dAtA, i, uint64(len(m.Skipped[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if m.Created != nil {
		{
			size, err := m.Created.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintGpgkey(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *GnuPGPublicKeyResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GnuPGPublicKeyResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GnuPGPublicKeyResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	return len(dAtA) - i, nil
}

func encodeVarintGpgkey(dAtA []byte, offset int, v uint64) int {
	offset -= sovGpgkey(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GnuPGPublicKeyQuery) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.KeyID)
	if l > 0 {
		n += 1 + l + sovGpgkey(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *GnuPGPublicKeyCreateRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Publickey != nil {
		l = m.Publickey.Size()
		n += 1 + l + sovGpgkey(uint64(l))
	}
	if m.Upsert {
		n += 2
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *GnuPGPublicKeyCreateResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Created != nil {
		l = m.Created.Size()
		n += 1 + l + sovGpgkey(uint64(l))
	}
	if len(m.Skipped) > 0 {
		for _, s := range m.Skipped {
			l = len(s)
			n += 1 + l + sovGpgkey(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *GnuPGPublicKeyResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovGpgkey(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozGpgkey(x uint64) (n int) {
	return sovGpgkey(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *GnuPGPublicKeyQuery) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGpgkey
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GnuPGPublicKeyQuery: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GnuPGPublicKeyQuery: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field KeyID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGpgkey
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGpgkey
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.KeyID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGpgkey(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGpgkey
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GnuPGPublicKeyCreateRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGpgkey
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GnuPGPublicKeyCreateRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GnuPGPublicKeyCreateRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Publickey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGpgkey
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGpgkey
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Publickey == nil {
				m.Publickey = &v1alpha1.GnuPGPublicKey{}
			}
			if err := m.Publickey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
					return ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Upsert = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipGpgkey(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGpgkey
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GnuPGPublicKeyCreateResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGpgkey
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GnuPGPublicKeyCreateResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GnuPGPublicKeyCreateResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Created", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthGpgkey
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthGpgkey
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Created == nil {
				m.Created = &v1alpha1.GnuPGPublicKeyList{}
			}
			if err := m.Created.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Skipped", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthGpgkey
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthGpgkey
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Skipped = append(m.Skipped, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipGpgkey(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGpgkey
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GnuPGPublicKeyResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowGpgkey
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GnuPGPublicKeyResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GnuPGPublicKeyResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipGpgkey(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthGpgkey
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipGpgkey(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowGpgkey
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
					return 0, ErrIntOverflowGpgkey
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowGpgkey
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
			if length < 0 {
				return 0, ErrInvalidLengthGpgkey
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupGpgkey
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthGpgkey
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthGpgkey        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowGpgkey          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupGpgkey = fmt.Errorf("proto: unexpected end of group")
)
