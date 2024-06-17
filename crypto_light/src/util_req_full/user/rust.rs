use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{OtpRecoveryKeysOutput, OtpRegister, UserDeviceList, UserInitServerOutput};

use crate::error::SdkLightError;
use crate::UserDataInt;

pub struct PrepareLoginOtpOutput
{
	pub master_key: crate::sdk_core::DeriveMasterKeyForAuth,
	pub auth_key: String,
}

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOut
{
	Direct(UserDataInt),
	Otp(PrepareLoginOtpOutput),
}

pub type Res = Result<String, SdkLightError>;
pub type VoidRes = Result<(), SdkLightError>;
pub type BoolRes = Result<bool, SdkLightError>;
pub type PreLoginRes = Result<PreLoginOut, SdkLightError>;
pub type LoginRes = Result<UserDataInt, SdkLightError>;
pub type InitRes = Result<UserInitServerOutput, SdkLightError>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, SdkLightError>;

pub type RegisterRawOtpRes = Result<OtpRegister, SdkLightError>;
pub type RegisterOtpRes = Result<(String, Vec<String>), SdkLightError>;
pub type OtpRecoveryKeyRes = Result<OtpRecoveryKeysOutput, SdkLightError>;
