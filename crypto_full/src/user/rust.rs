use alloc::string::String;

use sentc_crypto::{UserData, UserKeyData};
use sentc_crypto_common::user::{UserInitServerOutput, UserPublicKeyData, UserVerifyKeyData};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type BoolRes = Result<bool, SdkFullError>;
pub type LoginRes = Result<UserData, SdkFullError>;
pub type UserKeyFetchRes = Result<UserKeyData, SdkFullError>;
pub type UserPublicDataRes = Result<(UserPublicKeyData, UserVerifyKeyData), SdkFullError>;
pub type UserPublicKeyRes = Result<UserPublicKeyData, SdkFullError>;
pub type UserVerifyKeyRes = Result<UserVerifyKeyData, SdkFullError>;
pub type InitRes = Result<UserInitServerOutput, String>;
