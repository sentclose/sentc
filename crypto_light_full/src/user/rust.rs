use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{UserDeviceList, UserInitServerOutput};
use sentc_crypto_light::error::SdkLightError;
use sentc_crypto_light::UserDataInt;

pub type Res = Result<String, SdkLightError>;
pub type VoidRes = Result<(), SdkLightError>;
pub type BoolRes = Result<bool, SdkLightError>;
pub type LoginRes = Result<UserDataInt, SdkLightError>;
pub type InitRes = Result<UserInitServerOutput, SdkLightError>;
pub type DeviceListRes = Result<Vec<UserDeviceList>, SdkLightError>;
