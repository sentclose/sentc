use crate::SentcError;

#[derive(uniffi::Record)]
pub struct EncryptedHead
{
	pub id: String,
	pub sign_id: Option<String>,
	pub sign_alg: Option<String>,
}

#[derive(uniffi::Record)]
pub struct CryptoRawOutput
{
	pub head: String,
	pub data: Vec<u8>,
}

impl From<sentc_crypto_common::crypto::EncryptedHead> for EncryptedHead
{
	fn from(head: sentc_crypto_common::crypto::EncryptedHead) -> Self
	{
		let (sign_id, sign_alg) = match head.sign {
			None => (None, None),
			Some(s) => (Some(s.id), Some(s.alg)),
		};

		Self {
			id: head.id,
			sign_id,
			sign_alg,
		}
	}
}

#[uniffi::export]
pub fn split_head_and_encrypted_data(data: Vec<u8>) -> Result<EncryptedHead, SentcError>
{
	let (head, _data) = sentc_crypto::crypto::split_head_and_encrypted_data(&data)?;

	Ok(head.into())
}

#[uniffi::export]
pub fn split_head_and_encrypted_string(data: &str) -> Result<EncryptedHead, SentcError>
{
	let head = sentc_crypto::crypto::split_head_and_encrypted_string(data)?;

	Ok(head.into())
}

#[uniffi::export]
pub fn deserialize_head_from_string(head: &str) -> Result<EncryptedHead, SentcError>
{
	let head = sentc_crypto::crypto::deserialize_head_from_string(head)?;

	Ok(head.into())
}

#[uniffi::export]
pub fn encrypt_raw_symmetric(key: String, data: Vec<u8>, sign_key: Option<String>) -> Result<CryptoRawOutput, SentcError>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_symmetric(key.as_str(), &data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[uniffi::export]
pub fn decrypt_raw_symmetric(key: &str, encrypted_data: Vec<u8>, head: &str, verify_key_data: Option<String>) -> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_raw_symmetric(
		key,
		&encrypted_data,
		head,
		verify_key_data.as_deref(),
	)?)
}

#[uniffi::export]
pub fn encrypt_symmetric(key: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::encrypt_symmetric(
		key,
		&data,
		sign_key.as_deref(),
	)?)
}

#[uniffi::export]
pub fn decrypt_symmetric(key: &str, encrypted_data: Vec<u8>, verify_key_data: Option<String>) -> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_symmetric(
		key,
		&encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[uniffi::export]
pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: Option<String>) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::encrypt_string_symmetric(
		key,
		data,
		sign_key.as_deref(),
	)?)
}

#[uniffi::export]
pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_string_symmetric(
		key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[uniffi::export]
pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<CryptoRawOutput, SentcError>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_asymmetric(reply_public_key_data, &data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[uniffi::export]
pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: Vec<u8>, head: &str, verify_key_data: Option<String>)
	-> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_raw_asymmetric(
		private_key,
		&encrypted_data,
		head,
		verify_key_data.as_deref(),
	)?)
}

#[uniffi::export]
pub fn encrypt_asymmetric(reply_public_key_data: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::encrypt_asymmetric(
		reply_public_key_data,
		&data,
		sign_key.as_deref(),
	)?)
}

#[uniffi::export]
pub fn decrypt_asymmetric(private_key: &str, encrypted_data: Vec<u8>, verify_key_data: Option<String>) -> Result<Vec<u8>, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_asymmetric(
		private_key,
		&encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[uniffi::export]
pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: Option<String>) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::encrypt_string_asymmetric(
		reply_public_key_data,
		data,
		sign_key.as_deref(),
	)?)
}

#[uniffi::export]
pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_string_asymmetric(
		private_key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

//__________________________________________________________________________________________________

#[derive(uniffi::Record)]
pub struct NonRegisteredKeyOutput
{
	pub key: String,
	pub encrypted_key: String,
}

#[uniffi::export]
pub fn generate_non_register_sym_key(master_key: &str) -> Result<NonRegisteredKeyOutput, SentcError>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key(master_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[uniffi::export]
pub fn generate_non_register_sym_key_by_public_key(reply_public_key: &str) -> Result<NonRegisteredKeyOutput, SentcError>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key_by_public_key(reply_public_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[uniffi::export]
pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_sym_key(
		master_key,
		encrypted_symmetric_key_info,
	)?)
}

#[uniffi::export]
pub fn decrypt_sym_key_by_private_key(private_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto::decrypt_sym_key_by_private_key(
		private_key,
		encrypted_symmetric_key_info,
	)?)
}

//__________________________________________________________________________________________________
//searchable crypto

#[derive(uniffi::Record)]
pub struct SearchableCreateOutput
{
	pub hashes: Vec<String>,
	pub alg: String,
	pub key_id: String,
}

impl From<sentc_crypto_common::content_searchable::SearchableCreateOutput> for SearchableCreateOutput
{
	fn from(value: sentc_crypto_common::content_searchable::SearchableCreateOutput) -> Self
	{
		Self {
			hashes: value.hashes,
			alg: value.alg,
			key_id: value.key_id,
		}
	}
}

#[uniffi::export]
pub fn create_searchable_raw(key: &str, data: &str, full: bool, limit: Option<u32>) -> Result<Vec<String>, SentcError>
{
	let limit = limit.map(|l| l as usize);

	Ok(sentc_crypto::crypto_searchable::create_searchable_raw(
		key, data, full, limit,
	)?)
}

#[uniffi::export]
pub fn create_searchable(key: &str, data: &str, full: bool, limit: Option<u32>) -> Result<SearchableCreateOutput, SentcError>
{
	let limit = limit.map(|l| l as usize);

	let out = sentc_crypto::crypto_searchable::create_searchable(key, data, full, limit)?;

	Ok(out.into())
}

#[uniffi::export]
pub fn search(key: &str, data: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::crypto_searchable::search(key, data)?)
}

//__________________________________________________________________________________________________
//sortable

#[derive(uniffi::Record)]
pub struct SortableEncryptOutput
{
	pub number: u64,
	pub alg: String,
	pub key_id: String,
}

impl From<sentc_crypto_common::content_sortable::SortableEncryptOutput> for SortableEncryptOutput
{
	fn from(value: sentc_crypto_common::content_sortable::SortableEncryptOutput) -> Self
	{
		Self {
			number: value.number,
			alg: value.alg,
			key_id: value.key_id,
		}
	}
}

#[uniffi::export]
pub fn sortable_encrypt_raw_number(key: &str, data: u64) -> Result<u64, SentcError>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_number(key, data)?)
}

#[uniffi::export]
pub fn sortable_encrypt_number(key: &str, data: u64) -> Result<SortableEncryptOutput, SentcError>
{
	let out = sentc_crypto::crypto_sortable::encrypt_number(key, data)?;

	Ok(out.into())
}

#[uniffi::export]
pub fn sortable_encrypt_raw_string(key: &str, data: &str) -> Result<u64, SentcError>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_string(key, data, Some(4))?)
}

#[uniffi::export]
pub fn sortable_encrypt_string(key: &str, data: &str) -> Result<SortableEncryptOutput, SentcError>
{
	let out = sentc_crypto::crypto_sortable::encrypt_string(key, data, Some(4))?;

	Ok(out.into())
}
