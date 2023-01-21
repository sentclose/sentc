use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::content_searchable::ListSearchItem;
use sentc_crypto_common::SymKeyId;

pub type GenKeyRes = Result<(String, String), String>;
pub type KeyRes = Result<String, String>;
pub type KeysRes = Result<(Vec<String>, u128, SymKeyId), String>;
pub type VoidRes = Result<(), String>;
pub type SearchRes = Result<Vec<ListSearchItem>, String>;
