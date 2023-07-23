use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::SdkError;
use sentc_crypto_common::content_searchable::ListSearchItem;
use sentc_crypto_common::SymKeyId;
use sentc_crypto_utils::keys::SymKeyFormatInt;

pub type GenKeyRes = Result<(String, SymKeyFormatInt), SdkError>;
pub type KeyRes = Result<SymKeyFormatInt, SdkError>;
pub type KeysRes = Result<(Vec<SymKeyFormatInt>, u128, SymKeyId), SdkError>;
pub type VoidRes = Result<(), SdkError>;
pub type SearchRes = Result<Vec<ListSearchItem>, SdkError>;
