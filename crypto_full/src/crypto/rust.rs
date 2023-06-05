use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::keys::SymKeyFormatInt;
use sentc_crypto_common::content_searchable::ListSearchItem;
use sentc_crypto_common::SymKeyId;

use crate::error::SdkFullError;

pub type GenKeyRes = Result<(String, SymKeyFormatInt), SdkFullError>;
pub type KeyRes = Result<SymKeyFormatInt, SdkFullError>;
pub type KeysRes = Result<(Vec<SymKeyFormatInt>, u128, SymKeyId), SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type SearchRes = Result<Vec<ListSearchItem>, SdkFullError>;
