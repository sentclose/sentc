use base64ct::{Base64UrlUnpadded, Encoding};
use sentc_crypto_core::cryptomat::SearchableKey;
use sentc_crypto_utils::cryptomat::SearchableKeyWrapper;
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::search_key_composer;

use crate::core::hmac::HmacKey as CoreHmacKey;
use crate::util::HmacKey;

search_key_composer!(HmacKey, CoreHmacKey);

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
