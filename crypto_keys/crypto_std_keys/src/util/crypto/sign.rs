use alloc::string::ToString;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::SignHead;
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_core::cryptomat::{CryptoAlg, SignK};
use sentc_crypto_utils::cryptomat::{SignKCryptoWrapper, VerifyKFromUserKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::{Signature, VerifyKey as CoreVk};
use crate::util::{import_verify_key_from_pem_with_alg, SignKey, VerifyKey};

impl VerifyKFromUserKeyWrapper for VerifyKey
{
	type CoreVk = CoreVk;

	fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), SdkUtilError>
	{
		Ok(Signature::split_sig_and_data(alg, data_with_sign)?)
	}

	fn from_user_key(verify_key: &UserVerifyKeyData) -> Result<Self::CoreVk, SdkUtilError>
	{
		import_verify_key_from_pem_with_alg(&verify_key.verify_key_pem, &verify_key.verify_key_alg)
	}
}

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
