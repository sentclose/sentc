use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::crypto;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CryptoRawOutput
{
	head: String,
	data: Vec<u8>,
}

#[wasm_bindgen]
impl CryptoRawOutput
{
	pub fn get_head(&self) -> String
	{
		self.head.clone()
	}

	pub fn get_data(&self) -> Vec<u8>
	{
		self.data.clone()
	}
}

#[wasm_bindgen]
pub struct NonRegisteredKeyOutput
{
	key: String,
	encrypted_key: String,
}

#[wasm_bindgen]
impl NonRegisteredKeyOutput
{
	pub fn get_key(&self) -> String
	{
		self.key.clone()
	}

	pub fn get_encrypted_key(&self) -> String
	{
		self.encrypted_key.clone()
	}
}

#[wasm_bindgen]
pub struct KeyGenOutput
{
	key: String,
	key_id: String,
}

#[wasm_bindgen]
impl KeyGenOutput
{
	pub fn get_key(&self) -> String
	{
		self.key.clone()
	}

	pub fn get_key_id(&self) -> String
	{
		self.key_id.clone()
	}
}

#[wasm_bindgen]
pub fn split_head_and_encrypted_data(data: &[u8]) -> Result<JsValue, JsValue>
{
	let (head, _data) = crypto::split_head_and_encrypted_data(data)?;

	Ok(JsValue::from_serde(&head).unwrap())
}

#[wasm_bindgen]
pub fn split_head_and_encrypted_string(data: &str) -> Result<JsValue, JsValue>
{
	let head = crypto::split_head_and_encrypted_string(data)?;

	Ok(JsValue::from_serde(&head).unwrap())
}

#[wasm_bindgen]
pub fn deserialize_head_from_string(head: &str) -> Result<JsValue, JsValue>
{
	let head = crypto::deserialize_head_from_string(head)?;

	Ok(JsValue::from_serde(&head).unwrap())
}

#[wasm_bindgen]
pub fn encrypt_raw_symmetric(key: String, data: &[u8], sign_key: Option<String>) -> Result<CryptoRawOutput, JsValue>
{
	let (head, data) = crypto::encrypt_raw_symmetric(key.as_str(), data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_raw_symmetric(
		key,
		encrypted_data,
		head,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::encrypt_symmetric(key, data, sign_key.as_deref())?)
}

#[wasm_bindgen]
pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_symmetric(
		key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: Option<String>) -> Result<String, JsValue>
{
	Ok(crypto::encrypt_string_symmetric(key, data, sign_key.as_deref())?)
}

#[wasm_bindgen]
pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_string_symmetric(
		key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: Option<String>) -> Result<CryptoRawOutput, JsValue>
{
	let (head, data) = crypto::encrypt_raw_asymmetric(reply_public_key_data, data, sign_key.as_deref())?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_raw_asymmetric(
		private_key,
		encrypted_data,
		head,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::encrypt_asymmetric(
		reply_public_key_data,
		data,
		sign_key.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: Option<String>) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_asymmetric(
		private_key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: Option<String>) -> Result<String, JsValue>
{
	Ok(crypto::encrypt_string_asymmetric(
		reply_public_key_data,
		data,
		sign_key.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: Option<String>) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_string_asymmetric(
		private_key,
		encrypted_data,
		verify_key_data.as_deref(),
	)?)
}

#[wasm_bindgen]
pub fn generate_non_register_sym_key(master_key: &str) -> Result<NonRegisteredKeyOutput, JsValue>
{
	let (key, encrypted_key) = crypto::generate_non_register_sym_key(master_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[wasm_bindgen]
pub fn generate_non_register_sym_key_by_public_key(reply_public_key: &str) -> Result<NonRegisteredKeyOutput, JsValue>
{
	let (key, encrypted_key) = crypto::generate_non_register_sym_key_by_public_key(reply_public_key)?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

#[wasm_bindgen]
pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_sym_key(master_key, encrypted_symmetric_key_info)?)
}

#[wasm_bindgen]
pub fn decrypt_sym_key_by_private_key(private_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_sym_key_by_private_key(
		private_key,
		encrypted_symmetric_key_info,
	)?)
}

//__________________________________________________________________________________________________

//__________________________________________________________________________________________________
//searchable crypto

#[wasm_bindgen]
pub struct SearchableCreateOutput
{
	hashes: Vec<String>,
	alg: String,
	key_id: String,
}

#[wasm_bindgen]
impl SearchableCreateOutput
{
	pub fn get_hashes(&self) -> JsValue
	{
		JsValue::from_serde(&self.hashes).unwrap()
	}

	pub fn get_alg(&self) -> String
	{
		self.alg.clone()
	}

	pub fn get_key_id(&self) -> String
	{
		self.key_id.clone()
	}
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

#[wasm_bindgen]
pub fn create_searchable_raw(key: &str, data: &str, full: bool, limit: Option<usize>) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto::crypto_searchable::create_searchable_raw(key, data, full, limit)?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub fn create_searchable(key: &str, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, JsValue>
{
	let out = sentc_crypto::crypto_searchable::create_searchable(key, data, full, limit)?;

	Ok(out.into())
}

#[wasm_bindgen]
pub fn search(key: &str, data: &str) -> Result<String, JsValue>
{
	Ok(sentc_crypto::crypto_searchable::search(key, data)?)
}

//__________________________________________________________________________________________________
//sortable

#[wasm_bindgen]
pub struct SortableEncryptOutput
{
	number: u64,
	alg: String,
	key_id: String,
}

#[wasm_bindgen]
impl SortableEncryptOutput
{
	pub fn get_number(&self) -> u64
	{
		self.number
	}

	pub fn get_alg(&self) -> String
	{
		self.alg.clone()
	}

	pub fn get_key_id(&self) -> String
	{
		self.key_id.clone()
	}
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

#[wasm_bindgen]
pub fn sortable_encrypt_raw_number(key: &str, data: u64) -> Result<u64, JsValue>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_number(key, data)?)
}

#[wasm_bindgen]
pub fn sortable_encrypt_number(key: &str, data: u64) -> Result<SortableEncryptOutput, JsValue>
{
	let out = sentc_crypto::crypto_sortable::encrypt_number(key, data)?;

	Ok(out.into())
}

#[wasm_bindgen]
pub fn sortable_encrypt_raw_string(key: &str, data: &str) -> Result<u64, JsValue>
{
	Ok(sentc_crypto::crypto_sortable::encrypt_raw_string(key, data, Some(4))?)
}

#[wasm_bindgen]
pub fn sortable_encrypt_string(key: &str, data: &str) -> Result<SortableEncryptOutput, JsValue>
{
	let out = sentc_crypto::crypto_sortable::encrypt_string(key, data, Some(4))?;

	Ok(out.into())
}
