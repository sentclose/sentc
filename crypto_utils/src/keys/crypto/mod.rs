mod asym;
mod searchable;
mod sign;
mod sortable;
mod symmetric_key;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::Deref;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::{EncryptedHead, SignHead};
use sentc_crypto_common::SymKeyId;
use sentc_crypto_core::cryptomat::CryptoAlg;
use sentc_crypto_core::{HmacKey as CoreHmacKey, SortKeys as CoreSortableKey};
use serde::{Deserialize, Serialize};

use crate::error::SdkUtilError;
use crate::keys::{SignKey, SymmetricKey};

/**
Get the head and the data.

This can not only be used internally, to get the used key_id
 */
pub fn split_head_and_encrypted_data<'a, T: Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), SdkUtilError>
{
	let mut i = 0usize;
	for data_itr in data_with_head {
		if *data_itr == 0u8 {
			//the mark to split the head from the data
			//found the ii where to split head from data
			break;
		}

		i += 1;
	}

	let head = serde_json::from_slice(&data_with_head[..i])?;

	//ignore the zero byte
	Ok((head, &data_with_head[i + 1..]))
}

pub fn put_head_and_encrypted_data<T: Serialize>(head: &T, encrypted: &[u8]) -> Result<Vec<u8>, SdkUtilError>
{
	let head = serde_json::to_string(head).map_err(|_| SdkUtilError::JsonToStringFailed)?;

	let mut out = Vec::with_capacity(head.len() + 1 + encrypted.len());

	out.extend_from_slice(head.as_bytes());
	out.extend_from_slice(&[0u8]);
	out.extend_from_slice(encrypted);

	Ok(out)
}

fn get_head_from_keys(key: &SymmetricKey, sign_key: Option<&SignKey>) -> EncryptedHead
{
	if let Some(sk) = sign_key {
		let alg = sk.key.get_alg_str().to_string();

		let sign = SignHead {
			id: key.key_id.to_string(),
			alg,
		};

		EncryptedHead {
			id: key.key_id.to_string(),
			sign: Some(sign),
		}
	} else {
		EncryptedHead {
			id: key.key_id.to_string(),
			sign: None,
		}
	}
}

//__________________________________________________________________________________________________
//impl them here because they are only used when encryption is enabled

pub struct HmacKey
{
	pub key: CoreHmacKey,
	pub key_id: SymKeyId,
}

super::deref_impl!(HmacKey, CoreHmacKey);
super::to_string_impl!(HmacKey, HmacFormatExport);
super::from_string_impl!(HmacKey, HmacFormatExport);

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
		let key = Base64::encode_string(value.as_ref());

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

super::deref_impl!(SortableKey, CoreSortableKey);
super::to_string_impl!(SortableKey, SortableFormatExport);
super::from_string_impl!(SortableKey, SortableFormatExport);

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
		let key = Base64::encode_string(value.as_ref());

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
