use alloc::string::String;

use sentc_crypto::UserData;
use sentc_crypto_common::user::UserInitServerOutput;

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type LoginRes = Result<UserData, String>;
pub type UserPublicDataRes = Result<(String, String), String>;
pub type UserPublicKeyRes = Result<String, String>;
pub type UserVerifyKeyRes = Result<String, String>;
pub type InitRes = Result<UserInitServerOutput, String>;
