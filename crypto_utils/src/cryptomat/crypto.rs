use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use sentc_crypto_common::content_searchable::SearchableCreateOutput;
use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_common::crypto::{EncryptedHead, SignHead};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::cryptomat::{CryptoAlg, SearchableKey, SearchableKeyComposer, SortableKey, SortableKeyComposer};

use crate::cryptomat::{KeyToString, SignKWrapper};
use crate::error::SdkUtilError;

//searchable

pub trait SearchableKeyWrapper: FromStr + KeyToString
{
	type Inner: SearchableKey;

	fn get_id(&self) -> &str;

	fn get_key(&self) -> &Self::Inner;

	fn create_searchable_raw(&self, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, SdkUtilError>;

	fn create_searchable(&self, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, SdkUtilError>;

	fn search(&self, data: &str) -> Result<String, SdkUtilError>;
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
	fn encrypt_raw(&self, data: &[u8], sign_key: Option<&impl SignKWrapper>) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn encrypt_raw_with_aad(&self, data: &[u8], aad: &[u8], sign_key: Option<&impl SignKWrapper>) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn decrypt_raw(&self, encrypted_data: &[u8], head: &EncryptedHead, verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt_raw_with_aad(
		&self,
		encrypted_data: &[u8],
		aad: &[u8],
		head: &EncryptedHead,
		verify_key: Option<&UserVerifyKeyData>,
	) -> Result<Vec<u8>, SdkUtilError>;

	fn encrypt(&self, data: &[u8], sign_key: Option<&impl SignKWrapper>) -> Result<Vec<u8>, SdkUtilError>;

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8], sign_key: Option<&impl SignKWrapper>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt(&self, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt_with_aad(&self, encrypted_data_with_head: &[u8], aad: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn encrypt_string(&self, data: &str, sign_key: Option<&impl SignKWrapper>) -> Result<String, SdkUtilError>;

	fn encrypt_string_with_aad(&self, data: &str, aad: &str, sign_key: Option<&impl SignKWrapper>) -> Result<String, SdkUtilError>;

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

	fn decrypt(&self, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkUtilError>;

	fn decrypt_string(&self, encrypted_data_with_head: &str, verify_key: Option<&UserVerifyKeyData>) -> Result<String, SdkUtilError>;
}

pub trait PkFromUserKeyWrapper
{
	fn encrypt_raw_with_user_key(
		reply_public_key: &UserPublicKeyData,
		data: &[u8],
		sign_key: Option<&impl SignKWrapper>,
	) -> Result<(EncryptedHead, Vec<u8>), SdkUtilError>;

	fn encrypt_with_user_key(
		reply_public_key: &UserPublicKeyData,
		data: &[u8],
		sign_key: Option<&impl SignKWrapper>,
	) -> Result<Vec<u8>, SdkUtilError>;

	fn encrypt_string_with_user_key(
		reply_public_key: &UserPublicKeyData,
		data: &str,
		sign_key: Option<&impl SignKWrapper>,
	) -> Result<String, SdkUtilError>;
}

//__________________________________________________________________________________________________

pub trait SignKCryptoWrapper
{
	fn sign_with_head(&self, data: &[u8]) -> Result<(SignHead, Vec<u8>), SdkUtilError>;
}

pub trait VerifyKFromUserKeyWrapper
{
	fn verify_with_user_key<'a>(verify_key: &UserVerifyKeyData, data_with_sig: &'a [u8], sign_head: &SignHead) -> Result<&'a [u8], SdkUtilError>;

	fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), SdkUtilError>;
}
