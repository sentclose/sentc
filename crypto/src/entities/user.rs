use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::GroupHmacData;
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{DeviceId, SymKeyId, UserId};
use sentc_crypto_utils::keys::{PrivateKeyFormatInt, PublicKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt, VerifyKeyFormatInt};
use serde::{Deserialize, Serialize};

use crate::entities::group::GroupOutDataHmacKeyExport;
use crate::SdkError;

/**
# key storage structure for the rust feature

It can be used with other rust programs.

The different to the internally DoneLoginOutput ist that,
the KeyFormat is sued for each where, were the key id is saved too
 */
pub struct DeviceKeyDataInt
{
	pub private_key: PrivateKeyFormatInt,
	pub sign_key: SignKeyFormatInt,
	pub public_key: PublicKeyFormatInt,
	pub verify_key: VerifyKeyFormatInt,
	pub exported_public_key: UserPublicKeyData,
	pub exported_verify_key: UserVerifyKeyData,
}

pub struct UserKeyDataInt
{
	pub group_key: SymKeyFormatInt,
	pub private_key: PrivateKeyFormatInt,
	pub public_key: PublicKeyFormatInt,
	pub time: u128,
	pub sign_key: SignKeyFormatInt,
	pub verify_key: VerifyKeyFormatInt,
	pub exported_public_key: UserPublicKeyData,
	pub exported_verify_key: UserVerifyKeyData,
}

pub struct UserDataInt
{
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
	pub device_id: DeviceId,

	pub user_keys: Vec<UserKeyDataInt>,
	pub device_keys: DeviceKeyDataInt,
	pub hmac_keys: Vec<GroupHmacData>,
}

//==================================================================================================
//export

#[derive(Serialize, Deserialize)]
pub struct DeviceKeyDataExport
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl TryFrom<DeviceKeyDataInt> for DeviceKeyDataExport
{
	type Error = SdkError;

	fn try_from(value: DeviceKeyDataInt) -> Result<Self, Self::Error>
	{
		Ok(Self {
			private_key: value.private_key.to_string()?,
			public_key: value.public_key.to_string()?,
			sign_key: value.sign_key.to_string()?,
			verify_key: value.verify_key.to_string()?,
			exported_public_key: value
				.exported_public_key
				.to_string()
				.map_err(|_e| SdkError::JsonToStringFailed)?,
			exported_verify_key: value
				.exported_verify_key
				.to_string()
				.map_err(|_e| SdkError::JsonToStringFailed)?,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct UserKeyDataExport
{
	pub private_key: String,
	pub public_key: String,
	pub group_key: String,
	pub time: u128,
	pub group_key_id: SymKeyId,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_public_key_sig_key_id: Option<String>,
	pub exported_verify_key: String,
}

impl TryFrom<UserKeyDataInt> for UserKeyDataExport
{
	type Error = SdkError;

	fn try_from(value: UserKeyDataInt) -> Result<Self, Self::Error>
	{
		let group_key_id = value.group_key.key_id.clone();

		Ok(Self {
			private_key: value.private_key.to_string()?,
			public_key: value.public_key.to_string()?,
			group_key_id,
			group_key: value.group_key.to_string()?,
			time: value.time,
			sign_key: value.sign_key.to_string()?,
			verify_key: value.verify_key.to_string()?,
			exported_public_key: value
				.exported_public_key
				.to_string()
				.map_err(|_e| SdkError::JsonToStringFailed)?,
			exported_public_key_sig_key_id: value.exported_public_key.public_key_sig_key_id,
			exported_verify_key: value
				.exported_verify_key
				.to_string()
				.map_err(|_e| SdkError::JsonToStringFailed)?,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct UserDataExport
{
	pub user_keys: Vec<UserKeyDataExport>,
	pub device_keys: DeviceKeyDataExport,
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
	pub device_id: DeviceId,
	pub hmac_keys: Vec<GroupOutDataHmacKeyExport>,
}

impl TryFrom<UserDataInt> for UserDataExport
{
	type Error = SdkError;

	fn try_from(value: UserDataInt) -> Result<Self, Self::Error>
	{
		Ok(Self {
			user_keys: value
				.user_keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
			device_keys: value.device_keys.try_into()?,
			jwt: value.jwt,
			refresh_token: value.refresh_token,
			user_id: value.user_id,
			device_id: value.device_id,
			hmac_keys: value
				.hmac_keys
				.into_iter()
				.map(|k| k.try_into())
				.collect::<Result<_, SdkError>>()?,
		})
	}
}
