// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.12.4
// source: certificates.proto

package certificates

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// GCECertificateManifest represents a file we keep in the certificate private
// bucket that maps a CloudKMS key version name to its certificate file path.
// This is an append-only manifest. It should only update every key rotation,
// which is infrequent enough to not worry the file will become gigantic.
type GCECertificateManifest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entries []*GCECertificateManifest_Entry `protobuf:"bytes,1,rep,name=entries,proto3" json:"entries,omitempty"`
	// Given that CloudKMS disallows CryptoKeys with an asymmetric key purpose to
	// have a Primary version, we have to track it out of band in this manifest.
	PrimarySigningKeyVersionName string `protobuf:"bytes,2,opt,name=primary_signing_key_version_name,json=primarySigningKeyVersionName,proto3" json:"primary_signing_key_version_name,omitempty"`
	// We really don't want to have to rotate the root, but we'll store the
	// version it's at anyway.
	PrimaryRootKeyVersionName string `protobuf:"bytes,3,opt,name=primary_root_key_version_name,json=primaryRootKeyVersionName,proto3" json:"primary_root_key_version_name,omitempty"`
}

func (x *GCECertificateManifest) Reset() {
	*x = GCECertificateManifest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_certificates_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCECertificateManifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCECertificateManifest) ProtoMessage() {}

func (x *GCECertificateManifest) ProtoReflect() protoreflect.Message {
	mi := &file_certificates_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCECertificateManifest.ProtoReflect.Descriptor instead.
func (*GCECertificateManifest) Descriptor() ([]byte, []int) {
	return file_certificates_proto_rawDescGZIP(), []int{0}
}

func (x *GCECertificateManifest) GetEntries() []*GCECertificateManifest_Entry {
	if x != nil {
		return x.Entries
	}
	return nil
}

func (x *GCECertificateManifest) GetPrimarySigningKeyVersionName() string {
	if x != nil {
		return x.PrimarySigningKeyVersionName
	}
	return ""
}

func (x *GCECertificateManifest) GetPrimaryRootKeyVersionName() string {
	if x != nil {
		return x.PrimaryRootKeyVersionName
	}
	return ""
}

type GCECertificateManifest_Entry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyVersionName string `protobuf:"bytes,1,opt,name=key_version_name,json=keyVersionName,proto3" json:"key_version_name,omitempty"`
	ObjectPath     string `protobuf:"bytes,2,opt,name=object_path,json=objectPath,proto3" json:"object_path,omitempty"`
}

func (x *GCECertificateManifest_Entry) Reset() {
	*x = GCECertificateManifest_Entry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_certificates_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCECertificateManifest_Entry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCECertificateManifest_Entry) ProtoMessage() {}

func (x *GCECertificateManifest_Entry) ProtoReflect() protoreflect.Message {
	mi := &file_certificates_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCECertificateManifest_Entry.ProtoReflect.Descriptor instead.
func (*GCECertificateManifest_Entry) Descriptor() ([]byte, []int) {
	return file_certificates_proto_rawDescGZIP(), []int{0, 0}
}

func (x *GCECertificateManifest_Entry) GetKeyVersionName() string {
	if x != nil {
		return x.KeyVersionName
	}
	return ""
}

func (x *GCECertificateManifest_Entry) GetObjectPath() string {
	if x != nil {
		return x.ObjectPath
	}
	return ""
}

var File_certificates_proto protoreflect.FileDescriptor

var file_certificates_proto_rawDesc = []byte{
	0x0a, 0x12, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x5f, 0x76, 0x6d, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbf, 0x02, 0x0a, 0x16, 0x47, 0x43, 0x45, 0x43, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74,
	0x12, 0x47, 0x0a, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2d, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x5f, 0x76, 0x6d, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x43, 0x45, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x4d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2e, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x12, 0x46, 0x0a, 0x20, 0x70, 0x72, 0x69,
	0x6d, 0x61, 0x72, 0x79, 0x5f, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79,
	0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x1c, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x53, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x40, 0x0a, 0x1d, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x5f, 0x72, 0x6f, 0x6f,
	0x74, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x19, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72,
	0x79, 0x52, 0x6f, 0x6f, 0x74, 0x4b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x4e,
	0x61, 0x6d, 0x65, 0x1a, 0x52, 0x0a, 0x05, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x28, 0x0a, 0x10,
	0x6b, 0x65, 0x79, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6b, 0x65, 0x79, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x6f, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x50, 0x61, 0x74, 0x68, 0x42, 0x37, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x67, 0x63, 0x65,
	0x2d, 0x74, 0x63, 0x62, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_certificates_proto_rawDescOnce sync.Once
	file_certificates_proto_rawDescData = file_certificates_proto_rawDesc
)

func file_certificates_proto_rawDescGZIP() []byte {
	file_certificates_proto_rawDescOnce.Do(func() {
		file_certificates_proto_rawDescData = protoimpl.X.CompressGZIP(file_certificates_proto_rawDescData)
	})
	return file_certificates_proto_rawDescData
}

var file_certificates_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_certificates_proto_goTypes = []interface{}{
	(*GCECertificateManifest)(nil),       // 0: cloud_vmm_proto.GCECertificateManifest
	(*GCECertificateManifest_Entry)(nil), // 1: cloud_vmm_proto.GCECertificateManifest.Entry
}
var file_certificates_proto_depIdxs = []int32{
	1, // 0: cloud_vmm_proto.GCECertificateManifest.entries:type_name -> cloud_vmm_proto.GCECertificateManifest.Entry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_certificates_proto_init() }
func file_certificates_proto_init() {
	if File_certificates_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_certificates_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCECertificateManifest); i {
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
		file_certificates_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCECertificateManifest_Entry); i {
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
			RawDescriptor: file_certificates_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_certificates_proto_goTypes,
		DependencyIndexes: file_certificates_proto_depIdxs,
		MessageInfos:      file_certificates_proto_msgTypes,
	}.Build()
	File_certificates_proto = out.File
	file_certificates_proto_rawDesc = nil
	file_certificates_proto_goTypes = nil
	file_certificates_proto_depIdxs = nil
}
