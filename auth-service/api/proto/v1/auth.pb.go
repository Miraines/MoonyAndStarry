// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v6.31.1
// source: auth.proto

package authv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type HealthStatus int32

const (
	HealthStatus_UNKNOWN     HealthStatus = 0
	HealthStatus_SERVING     HealthStatus = 1
	HealthStatus_NOT_SERVING HealthStatus = 2
)

// Enum value maps for HealthStatus.
var (
	HealthStatus_name = map[int32]string{
		0: "UNKNOWN",
		1: "SERVING",
		2: "NOT_SERVING",
	}
	HealthStatus_value = map[string]int32{
		"UNKNOWN":     0,
		"SERVING":     1,
		"NOT_SERVING": 2,
	}
)

func (x HealthStatus) Enum() *HealthStatus {
	p := new(HealthStatus)
	*p = x
	return p
}

func (x HealthStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HealthStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_auth_proto_enumTypes[0].Descriptor()
}

func (HealthStatus) Type() protoreflect.EnumType {
	return &file_auth_proto_enumTypes[0]
}

func (x HealthStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HealthStatus.Descriptor instead.
func (HealthStatus) EnumDescriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{0}
}

type RegisterRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Email         string                 `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Password      string                 `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	Username      string                 `protobuf:"bytes,3,opt,name=username,proto3" json:"username,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RegisterRequest) Reset() {
	*x = RegisterRequest{}
	mi := &file_auth_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterRequest) ProtoMessage() {}

func (x *RegisterRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterRequest.ProtoReflect.Descriptor instead.
func (*RegisterRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{0}
}

func (x *RegisterRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *RegisterRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

func (x *RegisterRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

type RegisterResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AccessToken   string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	RefreshToken  string                 `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	AccessTtl     int64                  `protobuf:"varint,3,opt,name=access_ttl,json=accessTtl,proto3" json:"access_ttl,omitempty"`
	RefreshTtl    int64                  `protobuf:"varint,4,opt,name=refresh_ttl,json=refreshTtl,proto3" json:"refresh_ttl,omitempty"`
	UserId        string                 `protobuf:"bytes,5,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RegisterResponse) Reset() {
	*x = RegisterResponse{}
	mi := &file_auth_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RegisterResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterResponse) ProtoMessage() {}

func (x *RegisterResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterResponse.ProtoReflect.Descriptor instead.
func (*RegisterResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{1}
}

func (x *RegisterResponse) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *RegisterResponse) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *RegisterResponse) GetAccessTtl() int64 {
	if x != nil {
		return x.AccessTtl
	}
	return 0
}

func (x *RegisterResponse) GetRefreshTtl() int64 {
	if x != nil {
		return x.RefreshTtl
	}
	return 0
}

func (x *RegisterResponse) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

type LoginRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Email         string                 `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Password      string                 `protobuf:"bytes,2,opt,name=password,proto3" json:"password,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LoginRequest) Reset() {
	*x = LoginRequest{}
	mi := &file_auth_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LoginRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginRequest) ProtoMessage() {}

func (x *LoginRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginRequest.ProtoReflect.Descriptor instead.
func (*LoginRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{2}
}

func (x *LoginRequest) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *LoginRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type LoginResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AccessToken   string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	RefreshToken  string                 `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	AccessTtl     int64                  `protobuf:"varint,3,opt,name=access_ttl,json=accessTtl,proto3" json:"access_ttl,omitempty"`
	RefreshTtl    int64                  `protobuf:"varint,4,opt,name=refresh_ttl,json=refreshTtl,proto3" json:"refresh_ttl,omitempty"`
	UserId        string                 `protobuf:"bytes,5,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LoginResponse) Reset() {
	*x = LoginResponse{}
	mi := &file_auth_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LoginResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoginResponse) ProtoMessage() {}

func (x *LoginResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoginResponse.ProtoReflect.Descriptor instead.
func (*LoginResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{3}
}

func (x *LoginResponse) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *LoginResponse) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *LoginResponse) GetAccessTtl() int64 {
	if x != nil {
		return x.AccessTtl
	}
	return 0
}

func (x *LoginResponse) GetRefreshTtl() int64 {
	if x != nil {
		return x.RefreshTtl
	}
	return 0
}

func (x *LoginResponse) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

type TelegramAuthRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Id            int64                  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	FirstName     string                 `protobuf:"bytes,2,opt,name=first_name,json=firstName,proto3" json:"first_name,omitempty"`
	LastName      string                 `protobuf:"bytes,3,opt,name=last_name,json=lastName,proto3" json:"last_name,omitempty"`
	Username      string                 `protobuf:"bytes,4,opt,name=username,proto3" json:"username,omitempty"`
	PhotoUrl      string                 `protobuf:"bytes,5,opt,name=photo_url,json=photoUrl,proto3" json:"photo_url,omitempty"`
	AuthDate      int64                  `protobuf:"varint,6,opt,name=auth_date,json=authDate,proto3" json:"auth_date,omitempty"`
	Hash          string                 `protobuf:"bytes,7,opt,name=hash,proto3" json:"hash,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TelegramAuthRequest) Reset() {
	*x = TelegramAuthRequest{}
	mi := &file_auth_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TelegramAuthRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TelegramAuthRequest) ProtoMessage() {}

func (x *TelegramAuthRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TelegramAuthRequest.ProtoReflect.Descriptor instead.
func (*TelegramAuthRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{4}
}

func (x *TelegramAuthRequest) GetId() int64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *TelegramAuthRequest) GetFirstName() string {
	if x != nil {
		return x.FirstName
	}
	return ""
}

func (x *TelegramAuthRequest) GetLastName() string {
	if x != nil {
		return x.LastName
	}
	return ""
}

func (x *TelegramAuthRequest) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *TelegramAuthRequest) GetPhotoUrl() string {
	if x != nil {
		return x.PhotoUrl
	}
	return ""
}

func (x *TelegramAuthRequest) GetAuthDate() int64 {
	if x != nil {
		return x.AuthDate
	}
	return 0
}

func (x *TelegramAuthRequest) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

type RefreshRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RefreshToken  string                 `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RefreshRequest) Reset() {
	*x = RefreshRequest{}
	mi := &file_auth_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RefreshRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RefreshRequest) ProtoMessage() {}

func (x *RefreshRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RefreshRequest.ProtoReflect.Descriptor instead.
func (*RefreshRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{5}
}

func (x *RefreshRequest) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

type RefreshResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AccessToken   string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	RefreshToken  string                 `protobuf:"bytes,2,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RefreshResponse) Reset() {
	*x = RefreshResponse{}
	mi := &file_auth_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RefreshResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RefreshResponse) ProtoMessage() {}

func (x *RefreshResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RefreshResponse.ProtoReflect.Descriptor instead.
func (*RefreshResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{6}
}

func (x *RefreshResponse) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *RefreshResponse) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

type ValidateRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AccessToken   string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ValidateRequest) Reset() {
	*x = ValidateRequest{}
	mi := &file_auth_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ValidateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidateRequest) ProtoMessage() {}

func (x *ValidateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidateRequest.ProtoReflect.Descriptor instead.
func (*ValidateRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{7}
}

func (x *ValidateRequest) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

type ValidateResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	UserId        string                 `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Timestamp     int64                  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ValidateResponse) Reset() {
	*x = ValidateResponse{}
	mi := &file_auth_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ValidateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValidateResponse) ProtoMessage() {}

func (x *ValidateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValidateResponse.ProtoReflect.Descriptor instead.
func (*ValidateResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{8}
}

func (x *ValidateResponse) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *ValidateResponse) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

type LogoutRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RefreshToken  string                 `protobuf:"bytes,1,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	AccessToken   string                 `protobuf:"bytes,2,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogoutRequest) Reset() {
	*x = LogoutRequest{}
	mi := &file_auth_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogoutRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogoutRequest) ProtoMessage() {}

func (x *LogoutRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogoutRequest.ProtoReflect.Descriptor instead.
func (*LogoutRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{9}
}

func (x *LogoutRequest) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *LogoutRequest) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

type LogoutResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogoutResponse) Reset() {
	*x = LogoutResponse{}
	mi := &file_auth_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogoutResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogoutResponse) ProtoMessage() {}

func (x *LogoutResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogoutResponse.ProtoReflect.Descriptor instead.
func (*LogoutResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{10}
}

func (x *LogoutResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

type HealthCheckRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HealthCheckRequest) Reset() {
	*x = HealthCheckRequest{}
	mi := &file_auth_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HealthCheckRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthCheckRequest) ProtoMessage() {}

func (x *HealthCheckRequest) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthCheckRequest.ProtoReflect.Descriptor instead.
func (*HealthCheckRequest) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{11}
}

type HealthCheckResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        HealthStatus           `protobuf:"varint,1,opt,name=status,proto3,enum=auth.v1.HealthStatus" json:"status,omitempty"`
	Version       string                 `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
	Timestamp     int64                  `protobuf:"varint,3,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HealthCheckResponse) Reset() {
	*x = HealthCheckResponse{}
	mi := &file_auth_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HealthCheckResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthCheckResponse) ProtoMessage() {}

func (x *HealthCheckResponse) ProtoReflect() protoreflect.Message {
	mi := &file_auth_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthCheckResponse.ProtoReflect.Descriptor instead.
func (*HealthCheckResponse) Descriptor() ([]byte, []int) {
	return file_auth_proto_rawDescGZIP(), []int{12}
}

func (x *HealthCheckResponse) GetStatus() HealthStatus {
	if x != nil {
		return x.Status
	}
	return HealthStatus_UNKNOWN
}

func (x *HealthCheckResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *HealthCheckResponse) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

var File_auth_proto protoreflect.FileDescriptor

const file_auth_proto_rawDesc = "" +
	"\n" +
	"\n" +
	"auth.proto\x12\aauth.v1\"_\n" +
	"\x0fRegisterRequest\x12\x14\n" +
	"\x05email\x18\x01 \x01(\tR\x05email\x12\x1a\n" +
	"\bpassword\x18\x02 \x01(\tR\bpassword\x12\x1a\n" +
	"\busername\x18\x03 \x01(\tR\busername\"\xb3\x01\n" +
	"\x10RegisterResponse\x12!\n" +
	"\faccess_token\x18\x01 \x01(\tR\vaccessToken\x12#\n" +
	"\rrefresh_token\x18\x02 \x01(\tR\frefreshToken\x12\x1d\n" +
	"\n" +
	"access_ttl\x18\x03 \x01(\x03R\taccessTtl\x12\x1f\n" +
	"\vrefresh_ttl\x18\x04 \x01(\x03R\n" +
	"refreshTtl\x12\x17\n" +
	"\auser_id\x18\x05 \x01(\tR\x06userId\"@\n" +
	"\fLoginRequest\x12\x14\n" +
	"\x05email\x18\x01 \x01(\tR\x05email\x12\x1a\n" +
	"\bpassword\x18\x02 \x01(\tR\bpassword\"\xb0\x01\n" +
	"\rLoginResponse\x12!\n" +
	"\faccess_token\x18\x01 \x01(\tR\vaccessToken\x12#\n" +
	"\rrefresh_token\x18\x02 \x01(\tR\frefreshToken\x12\x1d\n" +
	"\n" +
	"access_ttl\x18\x03 \x01(\x03R\taccessTtl\x12\x1f\n" +
	"\vrefresh_ttl\x18\x04 \x01(\x03R\n" +
	"refreshTtl\x12\x17\n" +
	"\auser_id\x18\x05 \x01(\tR\x06userId\"\xcb\x01\n" +
	"\x13TelegramAuthRequest\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\x03R\x02id\x12\x1d\n" +
	"\n" +
	"first_name\x18\x02 \x01(\tR\tfirstName\x12\x1b\n" +
	"\tlast_name\x18\x03 \x01(\tR\blastName\x12\x1a\n" +
	"\busername\x18\x04 \x01(\tR\busername\x12\x1b\n" +
	"\tphoto_url\x18\x05 \x01(\tR\bphotoUrl\x12\x1b\n" +
	"\tauth_date\x18\x06 \x01(\x03R\bauthDate\x12\x12\n" +
	"\x04hash\x18\a \x01(\tR\x04hash\"5\n" +
	"\x0eRefreshRequest\x12#\n" +
	"\rrefresh_token\x18\x01 \x01(\tR\frefreshToken\"Y\n" +
	"\x0fRefreshResponse\x12!\n" +
	"\faccess_token\x18\x01 \x01(\tR\vaccessToken\x12#\n" +
	"\rrefresh_token\x18\x02 \x01(\tR\frefreshToken\"4\n" +
	"\x0fValidateRequest\x12!\n" +
	"\faccess_token\x18\x01 \x01(\tR\vaccessToken\"I\n" +
	"\x10ValidateResponse\x12\x17\n" +
	"\auser_id\x18\x01 \x01(\tR\x06userId\x12\x1c\n" +
	"\ttimestamp\x18\x02 \x01(\x03R\ttimestamp\"W\n" +
	"\rLogoutRequest\x12#\n" +
	"\rrefresh_token\x18\x01 \x01(\tR\frefreshToken\x12!\n" +
	"\faccess_token\x18\x02 \x01(\tR\vaccessToken\"*\n" +
	"\x0eLogoutResponse\x12\x18\n" +
	"\asuccess\x18\x01 \x01(\bR\asuccess\"\x14\n" +
	"\x12HealthCheckRequest\"|\n" +
	"\x13HealthCheckResponse\x12-\n" +
	"\x06status\x18\x01 \x01(\x0e2\x15.auth.v1.HealthStatusR\x06status\x12\x18\n" +
	"\aversion\x18\x02 \x01(\tR\aversion\x12\x1c\n" +
	"\ttimestamp\x18\x03 \x01(\x03R\ttimestamp*9\n" +
	"\fHealthStatus\x12\v\n" +
	"\aUNKNOWN\x10\x00\x12\v\n" +
	"\aSERVING\x10\x01\x12\x0f\n" +
	"\vNOT_SERVING\x10\x022\xc9\x03\n" +
	"\x04Auth\x12?\n" +
	"\bRegister\x12\x18.auth.v1.RegisterRequest\x1a\x19.auth.v1.RegisterResponse\x126\n" +
	"\x05Login\x12\x15.auth.v1.LoginRequest\x1a\x16.auth.v1.LoginResponse\x12D\n" +
	"\fTelegramAuth\x12\x1c.auth.v1.TelegramAuthRequest\x1a\x16.auth.v1.LoginResponse\x12<\n" +
	"\aRefresh\x12\x17.auth.v1.RefreshRequest\x1a\x18.auth.v1.RefreshResponse\x12?\n" +
	"\bValidate\x12\x18.auth.v1.ValidateRequest\x1a\x19.auth.v1.ValidateResponse\x129\n" +
	"\x06Logout\x12\x16.auth.v1.LogoutRequest\x1a\x17.auth.v1.LogoutResponse\x12H\n" +
	"\vHealthCheck\x12\x1b.auth.v1.HealthCheckRequest\x1a\x1c.auth.v1.HealthCheckResponseBEZCgithub.com/Miraines/MoonyAndStarry/auth-service/pkg/proto/v1;authv1b\x06proto3"

var (
	file_auth_proto_rawDescOnce sync.Once
	file_auth_proto_rawDescData []byte
)

func file_auth_proto_rawDescGZIP() []byte {
	file_auth_proto_rawDescOnce.Do(func() {
		file_auth_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_auth_proto_rawDesc), len(file_auth_proto_rawDesc)))
	})
	return file_auth_proto_rawDescData
}

var file_auth_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 13)
var file_auth_proto_goTypes = []any{
	(HealthStatus)(0),           // 0: auth.v1.HealthStatus
	(*RegisterRequest)(nil),     // 1: auth.v1.RegisterRequest
	(*RegisterResponse)(nil),    // 2: auth.v1.RegisterResponse
	(*LoginRequest)(nil),        // 3: auth.v1.LoginRequest
	(*LoginResponse)(nil),       // 4: auth.v1.LoginResponse
	(*TelegramAuthRequest)(nil), // 5: auth.v1.TelegramAuthRequest
	(*RefreshRequest)(nil),      // 6: auth.v1.RefreshRequest
	(*RefreshResponse)(nil),     // 7: auth.v1.RefreshResponse
	(*ValidateRequest)(nil),     // 8: auth.v1.ValidateRequest
	(*ValidateResponse)(nil),    // 9: auth.v1.ValidateResponse
	(*LogoutRequest)(nil),       // 10: auth.v1.LogoutRequest
	(*LogoutResponse)(nil),      // 11: auth.v1.LogoutResponse
	(*HealthCheckRequest)(nil),  // 12: auth.v1.HealthCheckRequest
	(*HealthCheckResponse)(nil), // 13: auth.v1.HealthCheckResponse
}
var file_auth_proto_depIdxs = []int32{
	0,  // 0: auth.v1.HealthCheckResponse.status:type_name -> auth.v1.HealthStatus
	1,  // 1: auth.v1.Auth.Register:input_type -> auth.v1.RegisterRequest
	3,  // 2: auth.v1.Auth.Login:input_type -> auth.v1.LoginRequest
	5,  // 3: auth.v1.Auth.TelegramAuth:input_type -> auth.v1.TelegramAuthRequest
	6,  // 4: auth.v1.Auth.Refresh:input_type -> auth.v1.RefreshRequest
	8,  // 5: auth.v1.Auth.Validate:input_type -> auth.v1.ValidateRequest
	10, // 6: auth.v1.Auth.Logout:input_type -> auth.v1.LogoutRequest
	12, // 7: auth.v1.Auth.HealthCheck:input_type -> auth.v1.HealthCheckRequest
	2,  // 8: auth.v1.Auth.Register:output_type -> auth.v1.RegisterResponse
	4,  // 9: auth.v1.Auth.Login:output_type -> auth.v1.LoginResponse
	4,  // 10: auth.v1.Auth.TelegramAuth:output_type -> auth.v1.LoginResponse
	7,  // 11: auth.v1.Auth.Refresh:output_type -> auth.v1.RefreshResponse
	9,  // 12: auth.v1.Auth.Validate:output_type -> auth.v1.ValidateResponse
	11, // 13: auth.v1.Auth.Logout:output_type -> auth.v1.LogoutResponse
	13, // 14: auth.v1.Auth.HealthCheck:output_type -> auth.v1.HealthCheckResponse
	8,  // [8:15] is the sub-list for method output_type
	1,  // [1:8] is the sub-list for method input_type
	1,  // [1:1] is the sub-list for extension type_name
	1,  // [1:1] is the sub-list for extension extendee
	0,  // [0:1] is the sub-list for field type_name
}

func init() { file_auth_proto_init() }
func file_auth_proto_init() {
	if File_auth_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_auth_proto_rawDesc), len(file_auth_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   13,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_auth_proto_goTypes,
		DependencyIndexes: file_auth_proto_depIdxs,
		EnumInfos:         file_auth_proto_enumTypes,
		MessageInfos:      file_auth_proto_msgTypes,
	}.Build()
	File_auth_proto = out.File
	file_auth_proto_goTypes = nil
	file_auth_proto_depIdxs = nil
}
