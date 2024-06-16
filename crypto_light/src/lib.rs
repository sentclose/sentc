#![no_std]

extern crate alloc;

pub mod error;
pub mod group;
pub mod user;
#[cfg(any(feature = "full_rustls", feature = "full_wasm"))]
pub mod util_req_full;

use alloc::string::String;

#[cfg(feature = "server_test")]
pub use sentc_crypto_common as sdk_common;
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_utils::cryptomat::KeyToString;
use sentc_crypto_utils::StdDeviceKeyDataInt;
use serde::{Deserialize, Serialize};
pub use {sentc_crypto_core as sdk_core, sentc_crypto_utils as sdk_utils};

use crate::error::SdkLightError;

pub struct UserDataInt
{
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
	pub device_id: DeviceId,

	pub device_keys: StdDeviceKeyDataInt,
}

#[derive(Serialize, Deserialize)]
pub struct UserDataExport
{
	pub device_keys: DeviceKeyDataExport,
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
	pub device_id: DeviceId,
}

impl TryFrom<UserDataInt> for UserDataExport
{
	type Error = SdkLightError;

	fn try_from(value: UserDataInt) -> Result<Self, Self::Error>
	{
		Ok(Self {
			device_keys: value.device_keys.try_into()?,
			jwt: value.jwt,
			refresh_token: value.refresh_token,
			user_id: value.user_id,
			device_id: value.device_id,
		})
	}
}

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

impl TryFrom<StdDeviceKeyDataInt> for DeviceKeyDataExport
{
	type Error = SdkLightError;

	fn try_from(value: StdDeviceKeyDataInt) -> Result<Self, Self::Error>
	{
		Ok(Self {
			private_key: value.private_key.to_string()?,
			public_key: value.public_key.to_string()?,
			sign_key: value.sign_key.to_string()?,
			verify_key: value.verify_key.to_string()?,
			exported_public_key: value
				.exported_public_key
				.to_string()
				.map_err(|_e| SdkLightError::JsonToStringFailed)?,
			exported_verify_key: value
				.exported_verify_key
				.to_string()
				.map_err(|_e| SdkLightError::JsonToStringFailed)?,
		})
	}
}
