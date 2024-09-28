use std::str::FromStr;

use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::SymKeyId;
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::{from_string_impl, to_string_impl};
use serde::{Deserialize, Serialize};

use crate::core::sortable::OpeSortableKey;

mod asym;
mod sign;
mod sortable;
mod symmetric_key;

pub struct SortableKey
{
	pub key: OpeSortableKey,
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
		let key = encode_block(value.key.as_ref());

		Self::Ope16 {
			key,
			key_id: value.key_id,
		}
	}
}

impl<'a> From<&'a SortableKey> for SortableFormatExport
{
	fn from(value: &'a SortableKey) -> Self
	{
		let key = encode_block(value.key.as_ref());

		Self::Ope16 {
			key,
			key_id: value.key_id.clone(),
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
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SortableKey {
					key: bytes.try_into()?,
					key_id,
				})
			},
		}
	}
}
