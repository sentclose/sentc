use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::keys::SymmetricKey;
use sentc_crypto::SdkError;
use sentc_crypto_common::SymKeyId;

pub type GenKeyRes = Result<(String, SymmetricKey), SdkError>;
pub type KeyRes = Result<SymmetricKey, SdkError>;
pub type KeysRes = Result<(Vec<SymmetricKey>, u128, SymKeyId), SdkError>;
pub type VoidRes = Result<(), SdkError>;
