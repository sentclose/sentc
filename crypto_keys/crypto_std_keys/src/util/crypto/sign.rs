use alloc::string::ToString;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::SignHead;
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_core::cryptomat::{CryptoAlg, SignK, VerifyK};
use sentc_crypto_utils::cryptomat::{SignKCryptoWrapper, VerifyKFromUserKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::Signature;
use crate::util::{import_verify_key_from_pem_with_alg, SignKey, VerifyKey};

impl VerifyKFromUserKeyWrapper for VerifyKey
{
	fn verify_with_user_key<'a>(verify_key: &UserVerifyKeyData, data_with_sig: &'a [u8], sign_head: &SignHead) -> Result<&'a [u8], SdkUtilError>
	{
		//use here the old way to get the verify key because we do not need to own the key id
		let verify_k = import_verify_key_from_pem_with_alg(verify_key.verify_key_pem.as_str(), verify_key.verify_key_alg.as_str())?;

		//check if the verify key is the right key id
		if verify_key.verify_key_id != sign_head.id {
			return Err(SdkUtilError::SigFoundNotKey);
		}

		//verify the data with the right key
		let (encrypted_data_without_sig, check) = verify_k.verify(data_with_sig)?;

		if !check {
			return Err(SdkUtilError::VerifyFailed);
		}

		Ok(encrypted_data_without_sig)
	}

	fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), SdkUtilError>
	{
		Ok(Signature::split_sig_and_data(alg, data_with_sign)?)
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
				alg: self.get_alg_str().to_string(),
			},
			sig,
		))
	}
}
