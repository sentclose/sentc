use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::group::{GroupKeyDataExport, GroupOutDataExport, GroupOutDataKeyExport};
use sentc_crypto_common::group::{
	GroupChildrenList,
	GroupDataCheckUpdateServerOutput,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupUserListItem,
	ListGroups,
};
use sentc_crypto_common::EncryptionKeyPairId;
use sentc_crypto_utils::group::GroupOutDataLightExport;
use serde::{Deserialize, Serialize};

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type DataRes = Result<GroupOutDataExport, String>;
pub type DataLightRes = Result<GroupOutDataLightExport, String>;
pub type KeyFetchRes = Result<Vec<GroupOutDataKeyExport>, String>;
pub type SingleKeyRes = Result<GroupOutDataKeyExport, String>;
pub type KeyRes = Result<GroupKeyDataExport, String>;
pub type GroupListRes = Result<Vec<ListGroups>, String>;
pub type ChildrenRes = Result<Vec<GroupChildrenList>, String>;
pub type SessionRes = Result<Option<String>, String>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, String>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, String>;
pub type KeyRotationRes = Result<Vec<KeyRotationGetOut>, String>;
pub type MemberRes = Result<Vec<GroupUserListItem>, String>;
pub type UserUpdateCheckRes = Result<GroupDataCheckUpdateServerOutput, String>;
pub type UserPublicKeyRes = Result<(String, EncryptionKeyPairId), String>;

#[derive(Serialize, Deserialize)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub new_group_key_id: String,
	pub encrypted_eph_key_key_id: EncryptionKeyPairId,
	pub server_output: String,

	pub signed_by_user_id: Option<String>,
	pub signed_by_user_sign_key_id: Option<String>,
	pub signed_by_user_sign_key_alg: Option<String>,
}
