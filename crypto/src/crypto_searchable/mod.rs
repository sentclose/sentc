use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use sentc_crypto_common::content_searchable::SearchCreateData;
use sentc_crypto_core::getting_alg_from_hmac_key;

use crate::util::HmacKeyFormatInt;
use crate::SdkError;

#[cfg(not(feature = "rust"))]
mod crypto_searchable;
#[cfg(feature = "rust")]
mod crypto_searchable_rust;

#[cfg(not(feature = "rust"))]
pub use self::crypto_searchable::{create_searchable, search};
#[cfg(feature = "rust")]
pub use self::crypto_searchable_rust::{create_searchable, search};

fn search_internally(key: &HmacKeyFormatInt, data: &str) -> Result<String, SdkError>
{
	hash_value_internally(key, data.as_bytes())
}

fn create_searchable_internally(
	key: &HmacKeyFormatInt,
	item_ref: &str,
	category: Option<&str>,
	data: &str,
	full: bool,
	limit: Option<usize>,
) -> Result<String, SdkError>
{
	let hashes = hash_full_internally(key, data, full, limit)?;

	let category = if let Some(c) = category { Some(c.to_string()) } else { None };

	let out = SearchCreateData {
		category,
		item_ref: item_ref.to_string(),
		hashes,
		alg: getting_alg_from_hmac_key(&key.key).to_string(),
		key_id: key.key_id.to_string(),
	};

	serde_json::to_string(&out).map_err(|_| SdkError::JsonToStringFailed)
}

fn hash_full_internally(key: &HmacKeyFormatInt, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SdkError>
{
	if data.is_empty() {
		return Err(SdkError::SearchableEncryptionDataNotFound);
	}

	if full {
		//create only one hash for 1:1 lookup. good for situations where the item should not be searched but checked
		let hash = hash_value_internally(key, data.as_bytes())?;

		return Ok(vec![hash]);
	}

	//how many bytes should be hashed
	let limit_length = if let Some(l) = limit {
		if l > data.len() {
			data.len()
		} else {
			l
		}
	} else {
		data.len()
	};

	if limit_length > 200 {
		return Err(SdkError::SearchableEncryptionDataTooLong);
	}

	let mut word_to_hash = Vec::with_capacity(limit_length);
	let mut hashed = Vec::with_capacity(limit_length);

	for (i, datum) in data.bytes().enumerate() {
		//make sure we not iterate over the limit when limit is set
		if i > limit_length {
			break;
		}

		//hash each char or byte of the string.
		//hash the next byte as an combination of the previous and the actual
		//like: word hello -> 1st hash('h'), 2nd hash('he'), 3rd hash('hel'), ...
		word_to_hash.push(datum);

		hashed.push(hash_value_internally(key, &word_to_hash)?);
	}

	Ok(hashed)
}

fn hash_value_internally(key: &HmacKeyFormatInt, data: &[u8]) -> Result<String, SdkError>
{
	let hash = sentc_crypto_core::crypto::encrypt_searchable(&key.key, data)?;

	Ok(Base64UrlUnpadded::encode_string(&hash))
}
