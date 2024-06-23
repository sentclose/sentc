use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::crypto::EncryptedHead;
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::cryptomat::{Pk, Sk};
use sentc_crypto_utils::cryptomat::{PkFromUserKeyWrapper, SignKWrapper, SkCryptoWrapper, VerifyKFromUserKeyWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::util::{PublicKey, SecretKey, VerifyKey};

impl PkFromUserKeyWrapper for PublicKey
{
	type Pk = Self;

	fn encrypt_raw_with_user_key(
		reply_public_key: &UserPublicKeyData,
		data: &[u8],
		sign_key: Option<&impl SignKWrapper>,
	) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>
	{
		let public_key = Self::try_from(reply_public_key)?;

		let encrypted = public_key.key.encrypt(data)?;

		if let Some(sk) = sign_key {
			let (sign_head, data_with_sign) = sk.sign_with_head(&encrypted)?;

			Ok((
				EncryptedHead {
					id: public_key.key_id,
					sign: Some(sign_head),
				},
				data_with_sign,
			))
		} else {
			Ok((
				EncryptedHead {
					id: public_key.key_id,
					sign: None,
				},
				encrypted,
			))
		}
	}

	fn encrypt_string_with_user_key(
		reply_public_key: &UserPublicKeyData,
		data: &str,
		sign_key: Option<&impl SignKWrapper>,
	) -> Result<String, SdkUtilError>
	{
		let encrypted = Self::encrypt_with_user_key(reply_public_key, data.as_bytes(), sign_key)?;

		Ok(encode_block(&encrypted))
	}

	fn from_user_key(reply_public_key: &UserPublicKeyData) -> Result<Self::Pk, SdkUtilError>
	{
		Self::try_from(reply_public_key)
	}
}

impl SkCryptoWrapper for SecretKey
{
	fn decrypt_raw(&self, encrypted_data: &[u8], head: &EncryptedHead, verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>
	{
		match &head.sign {
			None => Ok(self.key.decrypt(encrypted_data)?),
			Some(h) => {
				match verify_key {
					None => {
						let (_, encrypted_data_without_sig) = VerifyKey::split_sig_and_data(&h.alg, encrypted_data)?;
						Ok(self.key.decrypt(encrypted_data_without_sig)?)
					},
					Some(vk) => {
						let encrypted_data_without_sig = VerifyKey::verify_with_user_key(vk, encrypted_data, h)?;
						Ok(self.key.decrypt(encrypted_data_without_sig)?)
					},
				}
			},
		}
	}

	fn decrypt_string(&self, encrypted_data_with_head: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SdkUtilError>
	{
		let encrypted = decode_block(encrypted_data_with_head).map_err(|_| SdkUtilError::DecodeEncryptedDataFailed)?;

		let decrypted = self.decrypt(&encrypted, verify_key)?;

		String::from_utf8(decrypted).map_err(|_| SdkUtilError::DecodeEncryptedDataFailed)
	}
}
