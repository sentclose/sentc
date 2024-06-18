use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use sentc_crypto_common::content_searchable::SearchableCreateOutput;
use sentc_crypto_core::cryptomat::{CryptoAlg, SearchableKey, SearchableKeyComposer};
use sentc_crypto_utils::cryptomat::{SearchableKeyComposerWrapper, SearchableKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::HmacKey as CoreHmacKey;
use crate::util::HmacKey;

impl SearchableKeyComposerWrapper for HmacKey
{
	type SearchableKeyWrapper = Self;
	type Composer = CoreHmacKey;

	fn from_inner(inner: <<Self as SearchableKeyComposerWrapper>::Composer as SearchableKeyComposer>::Key, id: String) -> Self::SearchableKeyWrapper
	{
		Self {
			key: inner,
			key_id: id,
		}
	}
}

impl SearchableKeyWrapper for HmacKey
{
	type Inner = CoreHmacKey;

	fn get_id(&self) -> &str
	{
		&self.key_id
	}

	fn get_key(&self) -> &Self::Inner
	{
		&self.key
	}

	fn create_searchable_raw(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SdkUtilError>
	{
		self.hash_full_internally(data, full, limit)
	}

	fn create_searchable(&self, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, SdkUtilError>
	{
		let hashes = self.hash_full_internally(data, full, limit)?;

		Ok(SearchableCreateOutput {
			hashes,
			alg: self.get_alg_str().to_string(),
			key_id: self.key_id.to_string(),
		})
	}

	fn search(&self, data: &str) -> Result<String, SdkUtilError>
	{
		self.hash_value_internally(data.as_bytes())
	}
}

impl HmacKey
{
	fn hash_value_internally(&self, data: &[u8]) -> Result<String, SdkUtilError>
	{
		let hash = self.key.encrypt_searchable(data)?;

		Ok(Base64UrlUnpadded::encode_string(&hash))
	}

	fn hash_full_internally(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SdkUtilError>
	{
		if data.is_empty() {
			return Err(SdkUtilError::SearchableEncryptionDataNotFound);
		}

		if full {
			//create only one hash for 1:1 lookup. good for situations where the item should not be searched but checked
			let hash = self.hash_value_internally(data.as_bytes())?;

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
			return Err(SdkUtilError::SearchableEncryptionDataTooLong);
		}

		let mut word_to_hash = Vec::with_capacity(limit_length);
		let mut hashed = Vec::with_capacity(limit_length);

		for (i, datum) in data.bytes().enumerate() {
			//make sure we not iterate over the limit when limit is set
			if i > limit_length {
				break;
			}

			//hash each char or byte of the string.
			//hash the next byte as a combination of the previous and the actual
			//like: word hello -> 1st hash('h'), 2nd hash('he'), 3rd hash('hel'), ...
			word_to_hash.push(datum);

			hashed.push(self.hash_value_internally(&word_to_hash)?);
		}

		Ok(hashed)
	}
}
