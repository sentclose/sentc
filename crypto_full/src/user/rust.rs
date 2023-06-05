use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::user::{UserDataInt, UserKeyDataInt};
use sentc_crypto_common::user::{UserDeviceList, UserInitServerOutput, UserPublicKeyData, UserVerifyKeyData};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type BoolRes = Result<bool, SdkFullError>;
pub type LoginRes = Result<UserDataInt, SdkFullError>;
pub type UserKeyFetchRes = Result<UserKeyDataInt, SdkFullError>;
pub type UserPublicKeyRes = Result<UserPublicKeyData, SdkFullError>;
pub type UserVerifyKeyRes = Result<UserVerifyKeyData, SdkFullError>;
pub type InitRes = Result<UserInitServerOutput, SdkFullError>;
pub type SessionRes = Result<(Option<String>, UserPublicKeyData), SdkFullError>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, SdkFullError>;
