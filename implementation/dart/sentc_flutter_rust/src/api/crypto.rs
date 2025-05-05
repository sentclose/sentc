pub struct EncryptedHead
{
	pub id: String,
	pub sign_id: Option<String>,
	pub sign_alg: Option<String>,
}

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

pub fn split_head_and_encrypted_data(data: Vec<u8>) -> Result<EncryptedHead, String>
{
	let (head, _data) = sentc_crypto::crypto::split_head_and_encrypted_data(&data)?;

	Ok(head.into())
}

pub fn split_head_and_encrypted_string(data: &str) -> Result<EncryptedHead, String>
{
	let head = sentc_crypto::crypto::split_head_and_encrypted_string(data)?;

	Ok(head.into())
}

pub fn deserialize_head_from_string(head: &str) -> Result<EncryptedHead, String>
{
	let head = sentc_crypto::crypto::deserialize_head_from_string(head)?;

	Ok(head.into())
}

pub fn encrypt_raw_symmetric(key: String, data: Vec<u8>, sign_key: Option<String>) -> Result<CryptoRawOutput, String>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_symmetric(key.as_str(), &data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

pub fn decrypt_raw_symmetric(key: &str, encrypted_data: Vec<u8>, head: &str, verify_key_data: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::decrypt_raw_symmetric(key, &encrypted_data, head, verify_key_data.as_deref())
}

pub fn encrypt_symmetric(key: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::encrypt_symmetric(key, &data, sign_key.as_deref())
}

pub fn decrypt_symmetric(key: &str, encrypted_data: Vec<u8>, verify_key_data: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::decrypt_symmetric(key, &encrypted_data, verify_key_data.as_deref())
}

pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: Option<String>) -> Result<String, String>
{
	sentc_crypto::crypto::encrypt_string_symmetric(key, data, sign_key.as_deref())
}

pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, String>
{
	sentc_crypto::crypto::decrypt_string_symmetric(key, encrypted_data, verify_key_data.as_deref())
}

pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<CryptoRawOutput, String>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_asymmetric(reply_public_key_data, &data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: Vec<u8>, head: &str, verify_key_data: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::decrypt_raw_asymmetric(private_key, &encrypted_data, head, verify_key_data.as_deref())
}

pub fn encrypt_asymmetric(reply_public_key_data: &str, data: Vec<u8>, sign_key: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::encrypt_asymmetric(reply_public_key_data, &data, sign_key.as_deref())
}

pub fn decrypt_asymmetric(private_key: &str, encrypted_data: Vec<u8>, verify_key_data: Option<String>) -> Result<Vec<u8>, String>
{
	sentc_crypto::crypto::decrypt_asymmetric(private_key, &encrypted_data, verify_key_data.as_deref())
}

pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: Option<String>) -> Result<String, String>
{
	sentc_crypto::crypto::encrypt_string_asymmetric(reply_public_key_data, data, sign_key.as_deref())
}

pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, String>
{
	sentc_crypto::crypto::decrypt_string_asymmetric(private_key, encrypted_data, verify_key_data.as_deref())
}

//__________________________________________________________________________________________________

pub struct NonRegisteredKeyOutput
{
	pub key: String,
	pub encrypted_key: String,
}

pub fn generate_non_register_sym_key(master_key: &str) -> Result<NonRegisteredKeyOutput, String>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key(master_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

pub fn generate_non_register_sym_key_by_public_key(reply_public_key: &str) -> Result<NonRegisteredKeyOutput, String>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key_by_public_key(reply_public_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	sentc_crypto::crypto::decrypt_sym_key(master_key, encrypted_symmetric_key_info)
}

pub fn decrypt_sym_key_by_private_key(private_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	sentc_crypto::crypto::decrypt_sym_key_by_private_key(private_key, encrypted_symmetric_key_info)
}

//__________________________________________________________________________________________________

pub fn done_fetch_sym_key(master_key: &str, server_out: &str, non_registered: bool) -> Result<String, String>
{
	sentc_crypto::crypto::done_fetch_sym_key(master_key, server_out, non_registered)
}

pub fn done_fetch_sym_key_by_private_key(private_key: &str, server_out: &str, non_registered: bool) -> Result<String, String>
{
	sentc_crypto::crypto::done_fetch_sym_key_by_private_key(private_key, server_out, non_registered)
}

//__________________________________________________________________________________________________
//searchable crypto

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

pub fn create_searchable_raw(key: &str, data: &str, full: bool, limit: Option<u32>) -> Result<Vec<String>, String>
{
	let limit = limit.map(|l| l as usize);

	sentc_crypto::crypto_searchable::create_searchable_raw(key, data, full, limit)
}

pub fn create_searchable(key: &str, data: &str, full: bool, limit: Option<u32>) -> Result<SearchableCreateOutput, String>
{
	let limit = limit.map(|l| l as usize);

	let out = sentc_crypto::crypto_searchable::create_searchable(key, data, full, limit)?;

	Ok(out.into())
}

pub fn search(key: &str, data: &str) -> Result<String, String>
{
	sentc_crypto::crypto_searchable::search(key, data)
}

//__________________________________________________________________________________________________
//sortable

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

pub fn sortable_encrypt_raw_number(key: &str, data: u64) -> Result<u64, String>
{
	sentc_crypto::crypto_sortable::encrypt_raw_number(key, data)
}

pub fn sortable_encrypt_number(key: &str, data: u64) -> Result<SortableEncryptOutput, String>
{
	let out = sentc_crypto::crypto_sortable::encrypt_number(key, data)?;

	Ok(out.into())
}

pub fn sortable_encrypt_raw_string(key: &str, data: &str) -> Result<u64, String>
{
	sentc_crypto::crypto_sortable::encrypt_raw_string(key, data, Some(4))
}

pub fn sortable_encrypt_string(key: &str, data: &str) -> Result<SortableEncryptOutput, String>
{
	let out = sentc_crypto::crypto_sortable::encrypt_string(key, data, Some(4))?;

	Ok(out.into())
}
