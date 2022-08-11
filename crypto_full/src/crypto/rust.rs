use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::SymKeyFormat;

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type KeyRes = Result<SymKeyFormat, SdkFullError>;
pub type KeysRes = Result<(Vec<SymKeyFormat>, u128, SymKeyId), SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
