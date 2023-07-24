use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{UserDeviceList, UserInitServerOutput};
use sentc_crypto_light::UserDataExport;

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type LoginRes = Result<UserDataExport, String>;
pub type InitRes = Result<UserInitServerOutput, String>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, String>;
