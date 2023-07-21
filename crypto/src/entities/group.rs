use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{GroupHmacData, GroupKeyServerOutput, GroupSortableData};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::{EncryptionKeyPairId, GroupId, SymKeyId};
use sentc_crypto_utils::keys::{PrivateKeyFormatInt, PublicKeyFormatInt, SymKeyFormatInt};
use serde::{Deserialize, Serialize};

use crate::SdkError;

pub struct GroupOutData
{
	pub keys: Vec<GroupKeyServerOutput>,
	pub hmac_keys: Vec<GroupHmacData>,
	pub sortable_keys: Vec<GroupSortableData>,
	pub parent_group_id: Option<GroupId>,
	pub key_update: bool,
	pub created_time: u128,
	pub joined_time: u128,
	pub rank: i32,
	pub group_id: GroupId,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

pub struct GroupOutDataLight
{
	pub group_id: GroupId,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub created_time: u128,
	pub joined_time: u128,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

pub struct GroupKeyData
{
	pub group_key: SymKeyFormatInt,
	pub private_group_key: PrivateKeyFormatInt,
	pub public_group_key: PublicKeyFormatInt,
	pub exported_public_key: UserPublicKeyData,
	pub time: u128,
}

//==================================================================================================
//export

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataKeyExport
{
	pub private_key_id: EncryptionKeyPairId,
	pub key_data: String, //serde string
}

impl TryFrom<GroupKeyServerOutput> for GroupOutDataKeyExport
{
	type Error = SdkError;

	fn try_from(value: GroupKeyServerOutput) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_data: serde_json::to_string(&value)?,
			private_key_id: value.user_public_key_id,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataHmacKeyExport
{
	pub group_key_id: SymKeyId,
	pub key_data: String, //serde string
}

impl TryFrom<GroupHmacData> for GroupOutDataHmacKeyExport
{
	type Error = SdkError;

	fn try_from(value: GroupHmacData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_data: serde_json::to_string(&value)?,
			group_key_id: value.encrypted_hmac_encryption_key_id,
		})
	}
}

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataSortableEyExport
{
	pub group_key_id: SymKeyId,
	pub key_data: String, //serde string
}

impl TryFrom<GroupSortableData> for GroupOutDataSortableEyExport
{
	type Error = SdkError;

	fn try_from(value: GroupSortableData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_data: serde_json::to_string(&value)?,
			group_key_id: value.encrypted_sortable_encryption_key_id,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataExport
{
	pub group_id: GroupId,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub key_update: bool,
	pub created_time: u128,
	pub joined_time: u128,
	pub keys: Vec<GroupOutDataKeyExport>,
	pub hmac_keys: Vec<GroupOutDataHmacKeyExport>,
	pub sortable_keys: Vec<GroupOutDataSortableEyExport>,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

impl TryFrom<GroupOutData> for GroupOutDataExport
{
	type Error = SdkError;

	fn try_from(value: GroupOutData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			key_update: value.key_update,
			created_time: value.created_time,
			joined_time: value.joined_time,
			keys: value
				.keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			hmac_keys: value
				.hmac_keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			sortable_keys: value
				.sortable_keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataLightExport
{
	pub group_id: String,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub created_time: u128,
	pub joined_time: u128,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

impl From<GroupOutDataLight> for GroupOutDataLightExport
{
	fn from(value: GroupOutDataLight) -> Self
	{
		Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			created_time: value.created_time,
			joined_time: value.joined_time,
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		}
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct GroupKeyDataExport
{
	pub private_group_key: String,
	pub public_group_key: String,
	pub exported_public_key: String,
	pub group_key: String,
	pub time: u128,
	pub group_key_id: SymKeyId,
}

impl TryFrom<GroupKeyData> for GroupKeyDataExport
{
	type Error = SdkError;

	fn try_from(value: GroupKeyData) -> Result<Self, Self::Error>
	{
		let group_key_id = value.group_key.key_id.clone();

		Ok(Self {
			private_group_key: value.private_group_key.to_string()?,
			public_group_key: value.public_group_key.to_string()?,
			exported_public_key: value
				.exported_public_key
				.to_string()
				.map_err(|_e| SdkError::JsonToStringFailed)?,
			group_key: value.group_key.to_string()?,
			time: value.time,
			group_key_id,
		})
	}
}
