use alloc::string::String;

use sentc_crypto::KeyData;

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type KeyRes = Result<KeyData, String>;
