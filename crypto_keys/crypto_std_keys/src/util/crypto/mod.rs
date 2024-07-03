mod asym;
mod searchable;
mod sign;
mod sortable;
mod symmetric_key;

use alloc::string::String;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::SymKeyId;
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::{from_string_impl, to_string_impl};
use serde::{Deserialize, Serialize};

use crate::core::{HmacKey as CoreHmacKey, SortKeys as CoreSortableKey};

//__________________________________________________________________________________________________
//impl them here because they are only used when encryption is enabled

pub struct HmacKey
{
	pub key: CoreHmacKey,
	pub key_id: SymKeyId,
}

to_string_impl!(HmacKey, HmacFormatExport);
from_string_impl!(HmacKey, HmacFormatExport);

#[derive(Serialize, Deserialize)]
pub enum HmacFormatExport
{
	HmacSha256
	{
		key: String, key_id: SymKeyId
	},
}

impl From<HmacKey> for HmacFormatExport
{
	fn from(value: HmacKey) -> Self
	{
		let key = Base64::encode_string(value.key.as_ref());

		match value.key {
			CoreHmacKey::HmacSha256(_) => {
				Self::HmacSha256 {
					key,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl TryInto<HmacKey> for HmacFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<HmacKey, Self::Error>
	{
		match self {
			HmacFormatExport::HmacSha256 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(HmacKey {
					key: CoreHmacKey::hmac_sha256_from_bytes_owned(bytes)?,
					key_id,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

pub struct SortableKey
{
	pub key: CoreSortableKey,
	pub key_id: SymKeyId,
}

to_string_impl!(SortableKey, SortableFormatExport);
from_string_impl!(SortableKey, SortableFormatExport);

#[derive(Serialize, Deserialize)]
pub enum SortableFormatExport
{
	Ope16
	{
		key: String, key_id: SymKeyId
	},
}

impl From<SortableKey> for SortableFormatExport
{
	fn from(value: SortableKey) -> Self
	{
		let key = Base64::encode_string(value.key.as_ref());

		match value.key {
			CoreSortableKey::Ope(_) => {
				Self::Ope16 {
					key,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl TryInto<SortableKey> for SortableFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SortableKey, Self::Error>
	{
		match self {
			SortableFormatExport::Ope16 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SortableKey {
					key: CoreSortableKey::ope_key_from_bytes_owned(bytes)?,
					key_id,
				})
			},
		}
	}
}
