use alloc::string::String;

use sentc_crypto::group::GroupOutData;

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type BoolRes = Result<bool, String>;
pub type DataRes = Result<GroupOutData, String>;
