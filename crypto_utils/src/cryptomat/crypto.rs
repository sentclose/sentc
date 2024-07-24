use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;

use sentc_crypto_common::content_searchable::SearchableCreateOutput;
use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_common::crypto::{EncryptedHead, SignHead};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::cryptomat::{CryptoAlg, Pk, SearchableKey, SearchableKeyComposer, SortableKey, SortableKeyComposer, VerifyK};

use crate::cryptomat::{KeyToString, SignKWrapper};
use crate::error::SdkUtilError;
use crate::{put_head_and_encrypted_data, split_head_and_encrypted_data};

//searchable

pub trait SearchableKeyWrapper: FromStr + KeyToString
{
	type Inner: SearchableKey;

	fn get_id(&self) -> &str;

	fn get_key(&self) -> &Self::Inner;

	fn create_searchable_raw(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SdkUtilError>
	{
		if data.is_empty() {
			return Err(SdkUtilError::SearchableEncryptionDataNotFound);
		}

		if full {
			//create only one hash for 1:1 lookup. good for situations where the item should not be searched but checked
			let hash = self.search_bytes(data.as_bytes())?;

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

			hashed.push(self.search_bytes(&word_to_hash)?);
		}

		Ok(hashed)
	}

	fn create_searchable(&self, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, SdkUtilError>
	{
		let hashes = self.create_searchable_raw(data, full, limit)?;

		Ok(SearchableCreateOutput {
			hashes,
			alg: self.get_key().get_alg_str().to_string(),
			key_id: self.get_id().to_string(),
		})
	}

	fn search(&self, data: &str) -> Result<String, SdkUtilError>
	{
		self.search_bytes(data.as_bytes())
	}

	fn search_bytes(&self, data: &[u8]) -> Result<String, SdkUtilError>;
}

pub trait SearchableKeyComposerWrapper
{
	type SearchableKeyWrapper: SearchableKeyWrapper;
	type Composer: SearchableKeyComposer;

	fn from_inner(inner: <<Self as SearchableKeyComposerWrapper>::Composer as SearchableKeyComposer>::Key, id: String) -> Self::SearchableKeyWrapper;
}

//__________________________________________________________________________________________________
//sortable

pub trait SortableKeyWrapper: FromStr + KeyToString
{
	type Inner: SortableKey;

	fn get_id(&self) -> &str;

	fn get_key(&self) -> &Self::Inner;

	fn encrypt_number_raw(&self, data: u64) -> Result<u64, SdkUtilError>
	{
		Ok(self.get_key().encrypt_sortable(data)?)
	}

	fn encrypt_number(&self, data: u64) -> Result<SortableEncryptOutput, SdkUtilError>
	{
		let key = self.get_key();

		let number = key.encrypt_sortable(data)?;

		Ok(SortableEncryptOutput {
			number,
			alg: key.get_alg_str().to_string(),
			key_id: self.get_id().to_string(),
		})
	}

	fn encrypt_raw_string(&self, data: &str, max_len: Option<usize>) -> Result<u64, SdkUtilError>;

	fn encrypt_string(&self, data: &str, max_len: Option<usize>) -> Result<SortableEncryptOutput, SdkUtilError>;
}

pub trait SortableKeyComposerWrapper
{
	type SortableKeyWrapper: SortableKeyWrapper;
	type Composer: SortableKeyComposer;

	fn from_inner(inner: <<Self as SortableKeyComposerWrapper>::Composer as SortableKeyComposer>::Key, id: String) -> Self::SortableKeyWrapper;
}

//__________________________________________________________________________________________________

pub trait SymKeyCrypto
{
	type VerifyKey: VerifyKFromUserKeyWrapper;

	fn prepare_decrypt<'a>(encrypted_data: &'a [u8], head: &EncryptedHead, verify_key: Option<&UserVerifyKeyData>) -> Result<&'a [u8], SdkUtilError>
	{
		match &head.sign {
			None => Ok(encrypted_data),
			Some(h) => {
				match verify_key {
					Some(vk) => Self::VerifyKey::verify_with_user_key(vk, encrypted_data, h),
					None => {
						let (_, encrypted_data_without_sig) = Self::VerifyKey::split_sig_and_data(&h.alg, encrypted_data)?;
						Ok(encrypted_data_without_sig)
					},
				}
			},
		}
	}

	fn encrypt_raw(&self, data: &[u8]) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn encrypt_raw_with_sign(&self, data: &[u8], sign_key: &impl SignKWrapper) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn encrypt_raw_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn encrypt_raw_with_aad_with_sign(&self, data: &[u8], aad: &[u8], sign_key: &impl SignKWrapper)
		-> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn decrypt_raw(&self, encrypted_data: &[u8], head: &EncryptedHead, verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt_raw_with_aad(
		&self,
		encrypted_data: &[u8],
		aad: &[u8],
		head: &EncryptedHead,
		verify_key: Option<&UserVerifyKeyData>,
	) -> Result<Vec<u8>, SdkUtilError>;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted) = self.encrypt_raw(data)?;

		put_head_and_encrypted_data(&head, &encrypted)
	}

	fn encrypt_with_sign(&self, data: &[u8], sign_key: &impl SignKWrapper) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted) = self.encrypt_raw_with_sign(data, sign_key)?;

		put_head_and_encrypted_data(&head, &encrypted)
	}

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted) = self.encrypt_raw_with_aad(data, aad)?;

		put_head_and_encrypted_data(&head, &encrypted)
	}

	fn encrypt_with_aad_with_sign(&self, data: &[u8], aad: &[u8], sign_key: &impl SignKWrapper) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted) = self.encrypt_raw_with_aad_with_sign(data, aad, sign_key)?;

		put_head_and_encrypted_data(&head, &encrypted)
	}

	fn decrypt(&self, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted_data) = split_head_and_encrypted_data(encrypted_data_with_head)?;

		self.decrypt_raw(encrypted_data, &head, verify_key)
	}

	fn decrypt_with_aad(&self, encrypted_data_with_head: &[u8], aad: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted_data) = split_head_and_encrypted_data(encrypted_data_with_head)?;

		self.decrypt_raw_with_aad(encrypted_data, aad, &head, verify_key)
	}

	fn encrypt_string(&self, data: &str) -> Result<String, SdkUtilError>;

	fn encrypt_string_with_sign(&self, data: &str, sign_key: &impl SignKWrapper) -> Result<String, SdkUtilError>;

	fn encrypt_string_with_aad(&self, data: &str, aad: &str) -> Result<String, SdkUtilError>;

	fn encrypt_string_with_aad_with_sign(&self, data: &str, aad: &str, sign_key: &impl SignKWrapper) -> Result<String, SdkUtilError>;

	fn decrypt_string(&self, encrypted_data_with_head: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SdkUtilError>;

	fn decrypt_string_with_aad(
		&self,
		encrypted_data_with_head: &str,
		aad: &str,
		verify_key: Option<&UserVerifyKeyData>,
	) -> Result<String, SdkUtilError>;
}

//__________________________________________________________________________________________________

pub trait SkCryptoWrapper
{
	fn decrypt_raw(&self, encrypted_data: &[u8], head: &EncryptedHead, verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt(&self, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, encrypted_data) = split_head_and_encrypted_data(encrypted_data_with_head)?;

		self.decrypt_raw(encrypted_data, &head, verify_key)
	}

	fn decrypt_string(&self, encrypted_data_with_head: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SdkUtilError>;
}

pub trait PkFromUserKeyWrapper
{
	type CorePk: Pk;

	fn encrypt_raw_with_user_key(reply_public_key: &UserPublicKeyData, data: &[u8]) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>
	{
		let public_key = Self::from_user_key(reply_public_key)?;

		let encrypted = public_key.encrypt(data)?;

		Ok((
			EncryptedHead {
				id: reply_public_key.public_key_id.to_string(),
				sign: None,
			},
			encrypted,
		))
	}

	fn encrypt_raw_with_user_key_with_sign(
		reply_public_key: &UserPublicKeyData,
		data: &[u8],
		sign_key: &impl SignKWrapper,
	) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>
	{
		let public_key = Self::from_user_key(reply_public_key)?;

		let encrypted = public_key.encrypt(data)?;

		let (sign_head, data_with_sign) = sign_key.sign_with_head(&encrypted)?;

		Ok((
			EncryptedHead {
				id: reply_public_key.public_key_id.to_string(),
				sign: Some(sign_head),
			},
			data_with_sign,
		))
	}

	fn encrypt_with_user_key(reply_public_key: &UserPublicKeyData, data: &[u8]) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, data) = Self::encrypt_raw_with_user_key(reply_public_key, data)?;

		put_head_and_encrypted_data(&head, &data)
	}

	fn encrypt_with_user_key_with_sign(
		reply_public_key: &UserPublicKeyData,
		data: &[u8],
		sign_key: &impl SignKWrapper,
	) -> Result<Vec<u8>, SdkUtilError>
	{
		let (head, data) = Self::encrypt_raw_with_user_key_with_sign(reply_public_key, data, sign_key)?;

		put_head_and_encrypted_data(&head, &data)
	}

	fn encrypt_string_with_user_key(reply_public_key: &UserPublicKeyData, data: &str) -> Result<String, SdkUtilError>;

	fn encrypt_string_with_user_key_with_sign(
		reply_public_key: &UserPublicKeyData,
		data: &str,
		sign_key: &impl SignKWrapper,
	) -> Result<String, SdkUtilError>;

	fn from_user_key(reply_public_key: &UserPublicKeyData) -> Result<Self::CorePk, SdkUtilError>;
}

//__________________________________________________________________________________________________

pub trait SignKCryptoWrapper
{
	fn sign_with_head(&self, data: &[u8]) -> Result<(SignHead, Vec<u8>), SdkUtilError>;
}

pub trait VerifyKFromUserKeyWrapper
{
	type CoreVk: VerifyK;

	fn verify_with_user_key<'a>(verify_key: &UserVerifyKeyData, data_with_sig: &'a [u8], sign_head: &SignHead) -> Result<&'a [u8], SdkUtilError>
	{
		let vk = Self::from_user_key(verify_key)?;

		if verify_key.verify_key_id != sign_head.id {
			return Err(SdkUtilError::SigFoundNotKey);
		}

		let (encrypted_data_without_sig, check) = vk.verify(data_with_sig)?;

		if !check {
			return Err(SdkUtilError::VerifyFailed);
		}

		Ok(encrypted_data_without_sig)
	}

	fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), SdkUtilError>;

	fn from_user_key(verify_key: &UserVerifyKeyData) -> Result<Self::CoreVk, SdkUtilError>;
}
