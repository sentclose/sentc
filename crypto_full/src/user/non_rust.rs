use alloc::string::String;

use sentc_crypto::{UserData, UserKeyData};
use sentc_crypto_common::user::UserInitServerOutput;
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId};

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type LoginRes = Result<UserData, String>;
pub type UserKeyFetchRes = Result<UserKeyData, String>;
pub type UserPublicDataRes = Result<(String, EncryptionKeyPairId, String, SignKeyPairId), String>;
pub type UserPublicKeyRes = Result<(String, EncryptionKeyPairId), String>;
pub type UserVerifyKeyRes = Result<(String, SignKeyPairId), String>;
pub type InitRes = Result<UserInitServerOutput, String>;
pub type SessionRes = Result<Option<String>, String>;
