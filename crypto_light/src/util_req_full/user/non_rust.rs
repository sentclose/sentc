use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{OtpRecoveryKeysOutput, OtpRegister, UserDeviceList, UserInitServerOutput};

use crate::UserDataExport;

pub struct PrepareLoginOtpOutput
{
	pub master_key: String,
	pub auth_key: String,
}

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOut
{
	Direct(UserDataExport),
	Otp(PrepareLoginOtpOutput),
}

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type PreLoginRes = Result<PreLoginOut, String>;
pub type LoginRes = Result<UserDataExport, String>;
pub type InitRes = Result<UserInitServerOutput, String>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, String>;

pub type RegisterRawOtpRes = Result<OtpRegister, String>;
pub type RegisterOtpRes = Result<(String, Vec<String>), String>;
pub type OtpRecoveryKeyRes = Result<OtpRecoveryKeysOutput, String>;
