use alloc::string::String;

use sentc_crypto::KeyData;

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type BoolRes = Result<bool, SdkFullError>;
pub type KeyRes = Result<KeyData, SdkFullError>;
