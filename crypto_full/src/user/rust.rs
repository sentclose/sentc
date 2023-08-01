use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::user::{UserDataInt, UserKeyDataInt};
use sentc_crypto::SdkError;
use sentc_crypto_common::user::{UserDeviceList, UserInitServerOutput, UserPublicKeyData, UserVerifyKeyData};

pub struct PrepareLoginOtpOutput
{
	pub master_key: sentc_crypto::sdk_core::DeriveMasterKeyForAuth,
	pub auth_key: String,
}

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOut
{
	Direct(UserDataInt),
	Otp(PrepareLoginOtpOutput),
}

pub type Res = Result<String, SdkError>;
pub type VoidRes = Result<(), SdkError>;
pub type BoolRes = Result<bool, SdkError>;
pub type PreLoginRes = Result<PreLoginOut, SdkError>;
pub type LoginRes = Result<UserDataInt, SdkError>;
pub type UserKeyFetchRes = Result<UserKeyDataInt, SdkError>;
pub type UserPublicKeyRes = Result<UserPublicKeyData, SdkError>;
pub type UserVerifyKeyRes = Result<UserVerifyKeyData, SdkError>;
pub type InitRes = Result<UserInitServerOutput, SdkError>;
pub type SessionRes = Result<(Option<String>, UserPublicKeyData), SdkError>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, SdkError>;
