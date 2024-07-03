use std::str::FromStr;

use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_common::SymKeyId;
use sentc_crypto_core::cryptomat::SortableKeyComposer;
use sentc_crypto_utils::cryptomat::{KeyToString, SortableKeyComposerWrapper, SortableKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::{from_string_impl, to_string_try_impl};
use serde::{Deserialize, Serialize};

use crate::core::hmac::HmacKey as CoreHmacKey;
use crate::core::sortable::NonSortableKeys;

mod asym;
mod searchable;
mod sign;
mod symmetric_key;

pub struct HmacKey
{
	pub key: CoreHmacKey,
	pub key_id: SymKeyId,
}

to_string_try_impl!(HmacKey, HmacFormatExport);
from_string_impl!(HmacKey, HmacFormatExport);

#[derive(Serialize, Deserialize)]
pub struct HmacFormatExport
{
	key: String,
	key_id: SymKeyId,
}

impl TryFrom<HmacKey> for HmacFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: HmacKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id,
		})
	}
}

impl TryInto<HmacKey> for HmacFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<HmacKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		Ok(HmacKey {
			key: CoreHmacKey::try_from(bytes)?,
			key_id: self.key_id,
		})
	}
}

//__________________________________________________________________________________________________

//Sortable key is not complained with fips

pub struct SortableKey
{
	pub key: NonSortableKeys,
	pub key_id: SymKeyId,
}

impl KeyToString for SortableKey
{
	fn to_string(self) -> Result<String, SdkUtilError>
	{
		Ok(self.key_id)
	}
}

impl FromStr for SortableKey
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		Ok(Self {
			key: NonSortableKeys,
			key_id: s.to_string(),
		})
	}
}

impl SortableKeyComposerWrapper for SortableKey
{
	type SortableKeyWrapper = Self;
	type Composer = NonSortableKeys;

	fn from_inner(inner: <<Self as SortableKeyComposerWrapper>::Composer as SortableKeyComposer>::Key, id: String) -> Self::SortableKeyWrapper
	{
		Self {
			key: inner,
			key_id: id,
		}
	}
}

impl SortableKeyWrapper for SortableKey
{
	type Inner = NonSortableKeys;

	fn get_id(&self) -> &str
	{
		&self.key_id
	}

	fn get_key(&self) -> &Self::Inner
	{
		&self.key
	}

	fn encrypt_raw_string(&self, _data: &str, _max_len: Option<usize>) -> Result<u64, SdkUtilError>
	{
		Err(SdkUtilError::AlgNotFound)
	}

	fn encrypt_string(&self, _data: &str, _max_len: Option<usize>) -> Result<SortableEncryptOutput, SdkUtilError>
	{
		Err(SdkUtilError::AlgNotFound)
	}
}
