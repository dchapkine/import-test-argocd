// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        (unknown)
// source: apiclient/version/version.proto

// Version Service
//
// Version Service API returns the version of the API server.

package version

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// VersionMessage represents version of the Argo CD API server
type VersionMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version          string `protobuf:"bytes,1,opt,name=Version,proto3" json:"Version,omitempty"`
	BuildDate        string `protobuf:"bytes,2,opt,name=BuildDate,proto3" json:"BuildDate,omitempty"`
	GitCommit        string `protobuf:"bytes,3,opt,name=GitCommit,proto3" json:"GitCommit,omitempty"`
	GitTag           string `protobuf:"bytes,4,opt,name=GitTag,proto3" json:"GitTag,omitempty"`
	GitTreeState     string `protobuf:"bytes,5,opt,name=GitTreeState,proto3" json:"GitTreeState,omitempty"`
	GoVersion        string `protobuf:"bytes,6,opt,name=GoVersion,proto3" json:"GoVersion,omitempty"`
	Compiler         string `protobuf:"bytes,7,opt,name=Compiler,proto3" json:"Compiler,omitempty"`
	Platform         string `protobuf:"bytes,8,opt,name=Platform,proto3" json:"Platform,omitempty"`
	KustomizeVersion string `protobuf:"bytes,10,opt,name=KustomizeVersion,proto3" json:"KustomizeVersion,omitempty"`
	HelmVersion      string `protobuf:"bytes,11,opt,name=HelmVersion,proto3" json:"HelmVersion,omitempty"`
	KubectlVersion   string `protobuf:"bytes,12,opt,name=KubectlVersion,proto3" json:"KubectlVersion,omitempty"`
	JsonnetVersion   string `protobuf:"bytes,13,opt,name=JsonnetVersion,proto3" json:"JsonnetVersion,omitempty"`
}

func (x *VersionMessage) Reset() {
	*x = VersionMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_apiclient_version_version_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VersionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VersionMessage) ProtoMessage() {}

func (x *VersionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_apiclient_version_version_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VersionMessage.ProtoReflect.Descriptor instead.
func (*VersionMessage) Descriptor() ([]byte, []int) {
	return file_apiclient_version_version_proto_rawDescGZIP(), []int{0}
}

func (x *VersionMessage) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *VersionMessage) GetBuildDate() string {
	if x != nil {
		return x.BuildDate
	}
	return ""
}

func (x *VersionMessage) GetGitCommit() string {
	if x != nil {
		return x.GitCommit
	}
	return ""
}

func (x *VersionMessage) GetGitTag() string {
	if x != nil {
		return x.GitTag
	}
	return ""
}

func (x *VersionMessage) GetGitTreeState() string {
	if x != nil {
		return x.GitTreeState
	}
	return ""
}

func (x *VersionMessage) GetGoVersion() string {
	if x != nil {
		return x.GoVersion
	}
	return ""
}

func (x *VersionMessage) GetCompiler() string {
	if x != nil {
		return x.Compiler
	}
	return ""
}

func (x *VersionMessage) GetPlatform() string {
	if x != nil {
		return x.Platform
	}
	return ""
}

func (x *VersionMessage) GetKustomizeVersion() string {
	if x != nil {
		return x.KustomizeVersion
	}
	return ""
}

func (x *VersionMessage) GetHelmVersion() string {
	if x != nil {
		return x.HelmVersion
	}
	return ""
}

func (x *VersionMessage) GetKubectlVersion() string {
	if x != nil {
		return x.KubectlVersion
	}
	return ""
}

func (x *VersionMessage) GetJsonnetVersion() string {
	if x != nil {
		return x.JsonnetVersion
	}
	return ""
}

var File_apiclient_version_version_proto protoreflect.FileDescriptor

var file_apiclient_version_version_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x61, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2f, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x11, 0x61, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x96, 0x03, 0x0a, 0x0e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09,
	0x42, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x44, 0x61, 0x74, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x47, 0x69,
	0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x47,
	0x69, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x47, 0x69, 0x74, 0x54,
	0x61, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x47, 0x69, 0x74, 0x54, 0x61, 0x67,
	0x12, 0x22, 0x0a, 0x0c, 0x47, 0x69, 0x74, 0x54, 0x72, 0x65, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x47, 0x69, 0x74, 0x54, 0x72, 0x65, 0x65, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x47, 0x6f, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x47, 0x6f, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x12, 0x1a,
	0x0a, 0x08, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x2a, 0x0a, 0x10, 0x4b, 0x75,
	0x73, 0x74, 0x6f, 0x6d, 0x69, 0x7a, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x4b, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x69, 0x7a, 0x65, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x65, 0x6c, 0x6d, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x48, 0x65, 0x6c,
	0x6d, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x26, 0x0a, 0x0e, 0x4b, 0x75, 0x62, 0x65,
	0x63, 0x74, 0x6c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0e, 0x4b, 0x75, 0x62, 0x65, 0x63, 0x74, 0x6c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x12, 0x26, 0x0a, 0x0e, 0x4a, 0x73, 0x6f, 0x6e, 0x6e, 0x65, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x4a, 0x73, 0x6f, 0x6e, 0x6e, 0x65,
	0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x32, 0x6c, 0x0a, 0x0e, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5a, 0x0a, 0x07, 0x56, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x21, 0x2e,
	0x61, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x2e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x22, 0x14, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x0e, 0x12, 0x0c, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x42, 0xc0, 0x01, 0x0a, 0x15, 0x63, 0x6f, 0x6d, 0x2e, 0x61,
	0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x42, 0x0c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01,
	0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x72, 0x67,
	0x6f, 0x70, 0x72, 0x6f, 0x6a, 0x2f, 0x61, 0x72, 0x67, 0x6f, 0x2d, 0x63, 0x64, 0x2f, 0x76, 0x32,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0xa2, 0x02, 0x03, 0x41, 0x56, 0x58, 0xaa, 0x02, 0x11, 0x41,
	0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0xca, 0x02, 0x11, 0x41, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5c, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0xe2, 0x02, 0x1d, 0x41, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x5c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x12, 0x41, 0x70, 0x69, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
	0x3a, 0x3a, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_apiclient_version_version_proto_rawDescOnce sync.Once
	file_apiclient_version_version_proto_rawDescData = file_apiclient_version_version_proto_rawDesc
)

func file_apiclient_version_version_proto_rawDescGZIP() []byte {
	file_apiclient_version_version_proto_rawDescOnce.Do(func() {
		file_apiclient_version_version_proto_rawDescData = protoimpl.X.CompressGZIP(file_apiclient_version_version_proto_rawDescData)
	})
	return file_apiclient_version_version_proto_rawDescData
}

var file_apiclient_version_version_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_apiclient_version_version_proto_goTypes = []interface{}{
	(*VersionMessage)(nil), // 0: apiclient.version.VersionMessage
	(*emptypb.Empty)(nil),  // 1: google.protobuf.Empty
}
var file_apiclient_version_version_proto_depIdxs = []int32{
	1, // 0: apiclient.version.VersionService.Version:input_type -> google.protobuf.Empty
	0, // 1: apiclient.version.VersionService.Version:output_type -> apiclient.version.VersionMessage
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_apiclient_version_version_proto_init() }
func file_apiclient_version_version_proto_init() {
	if File_apiclient_version_version_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_apiclient_version_version_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VersionMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_apiclient_version_version_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_apiclient_version_version_proto_goTypes,
		DependencyIndexes: file_apiclient_version_version_proto_depIdxs,
		MessageInfos:      file_apiclient_version_version_proto_msgTypes,
	}.Build()
	File_apiclient_version_version_proto = out.File
	file_apiclient_version_version_proto_rawDesc = nil
	file_apiclient_version_version_proto_goTypes = nil
	file_apiclient_version_version_proto_depIdxs = nil
}
