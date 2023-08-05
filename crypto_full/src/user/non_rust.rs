use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::user::{UserDataExport, UserKeyDataExport};
use sentc_crypto_common::user::{OtpRecoveryKeysOutput, OtpRegister, UserDeviceList, UserInitServerOutput};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId};

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
pub type UserKeyFetchRes = Result<UserKeyDataExport, String>;
pub type UserPublicKeyRes = Result<(String, EncryptionKeyPairId, Option<SignKeyPairId>), String>;
pub type UserVerifyKeyRes = Result<String, String>;
pub type InitRes = Result<UserInitServerOutput, String>;
pub type SessionRes = Result<(Option<String>, String), String>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, String>;

pub type RegisterRawOtpRes = Result<OtpRegister, String>;
pub type RegisterOtpRes = Result<(String, Vec<String>), String>;
pub type OtpRecoveryKeyRes = Result<OtpRecoveryKeysOutput, String>;
