use sentc_crypto_common::crypto::SignHead;
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_core::cryptomat::{CryptoAlg, SignK};
use sentc_crypto_utils::cryptomat::{SignKCryptoWrapper, VerifyKFromUserKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::sign::{split_sig_and_data, Ed25519FIPSVerifyK, FIPS_OPENSSL_ED25519};
use crate::util::export::import_verify_key_from_pem_with_alg;
use crate::util::{SignKey, VerifyKey};

impl SignKCryptoWrapper for SignKey
{
	fn sign_with_head(&self, data: &[u8]) -> Result<(SignHead, Vec<u8>), SdkUtilError>
	{
		let sig = self.key.sign(data)?;

		Ok((
			SignHead {
				id: self.key_id.clone(),
				alg: self.key.get_alg_str().to_string(),
			},
			sig,
		))
	}
}

impl VerifyKFromUserKeyWrapper for VerifyKey
{
	type CoreVk = Ed25519FIPSVerifyK;

	fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), SdkUtilError>
	{
		if alg != FIPS_OPENSSL_ED25519 {
			return Err(SdkUtilError::AlgNotFound);
		}

		Ok(split_sig_and_data(data_with_sign)?)
	}

	fn from_user_key(verify_key: &UserVerifyKeyData) -> Result<Self::CoreVk, SdkUtilError>
	{
		import_verify_key_from_pem_with_alg(&verify_key.verify_key_pem, &verify_key.verify_key_alg)
	}
}
