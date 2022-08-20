use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::group::{GroupKeyData, GroupOutData, GroupOutDataKeys};
use sentc_crypto_common::group::{GroupDataCheckUpdateServerOutput, GroupInviteReqList, GroupJoinReqList, GroupUserListItem};
use sentc_crypto_common::EncryptionKeyPairId;
use serde::{Deserialize, Serialize};

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type DataRes = Result<GroupOutData, String>;
pub type KeyFetchRes = Result<Vec<GroupOutDataKeys>, String>;
pub type SingleKeyRes = Result<GroupOutDataKeys, String>;
pub type KeyRes = Result<GroupKeyData, String>;
pub type SessionRes = Result<Option<String>, String>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, String>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, String>;
pub type KeyRotationRes = Result<Vec<KeyRotationGetOut>, String>;
pub type MemberRes = Result<Vec<GroupUserListItem>, String>;
pub type UserUpdateCheckRes = Result<GroupDataCheckUpdateServerOutput, String>;

#[derive(Serialize, Deserialize)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub encrypted_eph_key_key_id: EncryptionKeyPairId,
	pub server_output: String,
}
