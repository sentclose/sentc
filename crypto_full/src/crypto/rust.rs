use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::SymKeyFormat;
use sentc_crypto_common::content_searchable::ListSearchItem;
use sentc_crypto_common::SymKeyId;

use crate::error::SdkFullError;

pub type GenKeyRes = Result<(String, SymKeyFormat), SdkFullError>;
pub type KeyRes = Result<SymKeyFormat, SdkFullError>;
pub type KeysRes = Result<(Vec<SymKeyFormat>, u128, SymKeyId), SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type SearchRes = Result<Vec<ListSearchItem>, SdkFullError>;
