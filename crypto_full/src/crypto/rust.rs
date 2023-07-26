use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::keys::SymKeyFormatInt;
use sentc_crypto::SdkError;
use sentc_crypto_common::SymKeyId;

pub type GenKeyRes = Result<(String, SymKeyFormatInt), SdkError>;
pub type KeyRes = Result<SymKeyFormatInt, SdkError>;
pub type KeysRes = Result<(Vec<SymKeyFormatInt>, u128, SymKeyId), SdkError>;
pub type VoidRes = Result<(), SdkError>;
