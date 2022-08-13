use alloc::string::String;

use sentc_crypto::KeyData;
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type BoolRes = Result<bool, SdkFullError>;
pub type KeyRes = Result<KeyData, SdkFullError>;
pub type UserPublicDataRes = Result<(UserPublicKeyData, UserVerifyKeyData), SdkFullError>;
pub type UserPublicKeyRes = Result<UserPublicKeyData, SdkFullError>;
pub type UserVerifyKeyRes = Result<UserVerifyKeyData, SdkFullError>;
