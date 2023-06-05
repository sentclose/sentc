use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::user::{UserDataExport, UserKeyDataExport};
use sentc_crypto_common::user::{UserDeviceList, UserInitServerOutput};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId};

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type LoginRes = Result<UserDataExport, String>;
pub type UserKeyFetchRes = Result<UserKeyDataExport, String>;
pub type UserPublicKeyRes = Result<(String, EncryptionKeyPairId, Option<SignKeyPairId>), String>;
pub type UserVerifyKeyRes = Result<String, String>;
pub type InitRes = Result<UserInitServerOutput, String>;
pub type SessionRes = Result<(Option<String>, String), String>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, String>;
