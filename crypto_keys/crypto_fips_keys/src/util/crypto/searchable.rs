use base64ct::{Base64UrlUnpadded, Encoding};
use sentc_crypto_core::cryptomat::{SearchableKey, SearchableKeyComposer};
use sentc_crypto_utils::cryptomat::{SearchableKeyComposerWrapper, SearchableKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::hmac::HmacKey as CoreHmacKey;
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

	fn search_bytes(&self, data: &[u8]) -> Result<String, SdkUtilError>
	{
		let hash = self.key.encrypt_searchable(data)?;

		Ok(Base64UrlUnpadded::encode_string(&hash))
	}
}
