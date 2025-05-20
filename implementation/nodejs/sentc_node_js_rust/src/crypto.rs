use napi::bindgen_prelude::*;

#[napi(object)]
pub struct SignHead
{
	pub id: String,
	pub alg: String,
}

impl From<sentc_crypto_common::crypto::SignHead> for SignHead
{
	fn from(value: sentc_crypto_common::crypto::SignHead) -> Self
	{
		Self {
			id: value.id,
			alg: value.alg,
		}
	}
}

#[napi(object)]
pub struct EncryptedHead
{
	pub id: String,
	pub sign: Option<SignHead>,
}

impl From<sentc_crypto_common::crypto::EncryptedHead> for EncryptedHead
{
	fn from(head: sentc_crypto_common::crypto::EncryptedHead) -> Self
	{
		Self {
			id: head.id,
			sign: head.sign.map(|s| s.into()),
		}
	}
}

#[napi(object)]
pub struct CryptoRawOutput
{
	pub head: String,
	pub data: Buffer,
}

#[napi]
pub fn split_head_and_encrypted_data(data: BufferSlice) -> Result<EncryptedHead>
{
	let (head, _data) = sentc_crypto::crypto::split_head_and_encrypted_data(&data).map_err(Error::from_reason)?;

	Ok(head.into())
}

#[napi]
pub fn split_head_and_encrypted_string(data: String) -> Result<EncryptedHead>
{
	let head = sentc_crypto::crypto::split_head_and_encrypted_string(&data).map_err(Error::from_reason)?;

	Ok(head.into())
}

#[napi]
pub fn deserialize_head_from_string(head: String) -> Result<EncryptedHead>
{
	let head = sentc_crypto::crypto::deserialize_head_from_string(&head).map_err(Error::from_reason)?;

	Ok(head.into())
}

#[napi]
pub fn encrypt_raw_symmetric(key: String, data: BufferSlice, sign_key: Option<String>) -> Result<CryptoRawOutput>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_symmetric(&key, &data, sign_key.as_deref()).map_err(Error::from_reason)?;

	Ok(CryptoRawOutput {
		head,
		data: data.into(),
	})
}

#[napi]
pub fn decrypt_raw_symmetric(key: String, encrypted_data: BufferSlice, head: String, verify_key_data: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::decrypt_raw_symmetric(&key, &encrypted_data, &head, verify_key_data.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn encrypt_symmetric(key: String, data: BufferSlice, sign_key: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::encrypt_symmetric(&key, &data, sign_key.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn decrypt_symmetric(key: String, encrypted_data: BufferSlice, verify_key_data: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::decrypt_symmetric(&key, &encrypted_data, verify_key_data.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn encrypt_string_symmetric(key: String, data: String, sign_key: Option<String>) -> Result<String>
{
	sentc_crypto::crypto::encrypt_string_symmetric(&key, &data, sign_key.as_deref()).map_err(Error::from_reason)
}

#[napi]
pub fn decrypt_string_symmetric(key: String, encrypted_data: String, verify_key_data: Option<String>) -> Result<String>
{
	sentc_crypto::crypto::decrypt_string_symmetric(&key, &encrypted_data, verify_key_data.as_deref()).map_err(Error::from_reason)
}

#[napi]
pub fn encrypt_raw_asymmetric(reply_public_key_data: String, data: BufferSlice, sign_key: Option<String>) -> Result<CryptoRawOutput>
{
	let (head, data) =
		sentc_crypto::crypto::encrypt_raw_asymmetric(&reply_public_key_data, &data, sign_key.as_deref()).map_err(Error::from_reason)?;

	Ok(CryptoRawOutput {
		head,
		data: data.into(),
	})
}

#[napi]
pub fn decrypt_raw_asymmetric(private_key: String, encrypted_data: BufferSlice, head: String, verify_key_data: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::decrypt_raw_asymmetric(&private_key, &encrypted_data, &head, verify_key_data.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn encrypt_asymmetric(reply_public_key_data: String, data: BufferSlice, sign_key: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::encrypt_asymmetric(&reply_public_key_data, &data, sign_key.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn decrypt_asymmetric(private_key: String, encrypted_data: BufferSlice, verify_key_data: Option<String>) -> Result<Buffer>
{
	Ok(
		sentc_crypto::crypto::decrypt_asymmetric(&private_key, &encrypted_data, verify_key_data.as_deref())
			.map_err(Error::from_reason)?
			.into(),
	)
}

#[napi]
pub fn encrypt_string_asymmetric(reply_public_key_data: String, data: String, sign_key: Option<String>) -> Result<String>
{
	sentc_crypto::crypto::encrypt_string_asymmetric(&reply_public_key_data, &data, sign_key.as_deref()).map_err(Error::from_reason)
}

#[napi]
pub fn decrypt_string_asymmetric(private_key: String, encrypted_data: String, verify_key_data: Option<String>) -> Result<String>
{
	sentc_crypto::crypto::decrypt_string_asymmetric(&private_key, &encrypted_data, verify_key_data.as_deref()).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct NonRegisteredKeyOutput
{
	pub key: String,
	pub encrypted_key: String,
}

#[napi]
pub fn generate_non_register_sym_key(master_key: String) -> Result<NonRegisteredKeyOutput>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key(&master_key).map_err(Error::from_reason)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[napi]
pub fn generate_non_register_sym_key_by_public_key(reply_public_key: String) -> Result<NonRegisteredKeyOutput>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key_by_public_key(&reply_public_key).map_err(Error::from_reason)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[napi]
pub fn decrypt_sym_key(master_key: String, encrypted_symmetric_key_info: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_sym_key(&master_key, &encrypted_symmetric_key_info).map_err(Error::from_reason)
}

#[napi]
pub fn decrypt_sym_key_by_private_key(private_key: String, encrypted_symmetric_key_info: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_sym_key_by_private_key(&private_key, &encrypted_symmetric_key_info).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi]
pub fn done_fetch_sym_key(master_key: String, server_out: String, non_registered: bool) -> Result<String>
{
	sentc_crypto::crypto::done_fetch_sym_key(&master_key, &server_out, non_registered).map_err(Error::from_reason)
}

#[napi]
pub fn done_fetch_sym_key_by_private_key(private_key: String, server_out: String, non_registered: bool) -> Result<String>
{
	sentc_crypto::crypto::done_fetch_sym_key_by_private_key(&private_key, &server_out, non_registered).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//searchable crypto

#[napi(object)]
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

#[napi]
pub fn create_searchable_raw(key: String, data: String, full: bool, limit: Option<u32>) -> Result<Vec<String>>
{
	let limit = limit.map(|l| l as usize);

	sentc_crypto::crypto_searchable::create_searchable_raw(&key, &data, full, limit).map_err(Error::from_reason)
}

#[napi]
pub fn create_searchable(key: String, data: String, full: bool, limit: Option<u32>) -> Result<SearchableCreateOutput>
{
	let limit = limit.map(|l| l as usize);

	let out = sentc_crypto::crypto_searchable::create_searchable(&key, &data, full, limit).map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub fn search(key: String, data: String) -> Result<String>
{
	sentc_crypto::crypto_searchable::search(&key, &data).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//sortable

#[napi(object)]
pub struct SortableEncryptOutput
{
	pub number: i64,
	pub alg: String,
	pub key_id: String,
}

impl From<sentc_crypto_common::content_sortable::SortableEncryptOutput> for SortableEncryptOutput
{
	fn from(value: sentc_crypto_common::content_sortable::SortableEncryptOutput) -> Self
	{
		Self {
			number: value.number as i64,
			alg: value.alg,
			key_id: value.key_id,
		}
	}
}

#[napi]
pub fn sortable_encrypt_raw_number(key: String, data: i64) -> Result<i64>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_number(&key, data as u64).map_err(Error::from_reason)? as i64)
}

#[napi]
pub fn sortable_encrypt_number(key: String, data: i64) -> Result<SortableEncryptOutput>
{
	let out = sentc_crypto::crypto_sortable::encrypt_number(&key, data as u64).map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub fn sortable_encrypt_raw_string(key: String, data: String) -> Result<i64>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_string(&key, &data, Some(4)).map_err(Error::from_reason)? as i64)
}

#[napi]
pub fn sortable_encrypt_string(key: String, data: String) -> Result<SortableEncryptOutput>
{
	let out = sentc_crypto::crypto_sortable::encrypt_string(&key, &data, Some(4)).map_err(Error::from_reason)?;

	Ok(out.into())
}
