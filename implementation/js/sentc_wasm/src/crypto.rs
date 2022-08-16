use alloc::string::{String, ToString};
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
pub fn encrypt_raw_symmetric(key: String, data: &[u8], sign_key: &str) -> Result<CryptoRawOutput, JsValue>
{
	let (head, data) = crypto::encrypt_raw_symmetric(key.as_str(), data, sign_key)?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_raw_symmetric(
		key,
		encrypted_data,
		head,
		verify_key_data,
	)?)
}

#[wasm_bindgen]
pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::encrypt_symmetric(key, data, sign_key)?)
}

#[wasm_bindgen]
pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_symmetric(key, encrypted_data, verify_key_data)?)
}

#[wasm_bindgen]
pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: &str) -> Result<String, JsValue>
{
	Ok(crypto::encrypt_string_symmetric(key, data, sign_key)?)
}

#[wasm_bindgen]
pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_string_symmetric(
		key,
		encrypted_data,
		verify_key_data,
	)?)
}

#[wasm_bindgen]
pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<CryptoRawOutput, JsValue>
{
	let (head, data) = crypto::encrypt_raw_asymmetric(reply_public_key_data, data, sign_key)?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_raw_asymmetric(
		private_key,
		encrypted_data,
		head,
		verify_key_data,
	)?)
}

#[wasm_bindgen]
pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::encrypt_asymmetric(reply_public_key_data, data, sign_key)?)
}

#[wasm_bindgen]
pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, JsValue>
{
	Ok(crypto::decrypt_asymmetric(
		private_key,
		encrypted_data,
		verify_key_data,
	)?)
}

#[wasm_bindgen]
pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: &str) -> Result<String, JsValue>
{
	Ok(crypto::encrypt_string_asymmetric(
		reply_public_key_data,
		data,
		sign_key,
	)?)
}

#[wasm_bindgen]
pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_string_asymmetric(
		private_key,
		encrypted_data,
		verify_key_data,
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
pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, JsValue>
{
	Ok(crypto::decrypt_sym_key(master_key, encrypted_symmetric_key_info)?)
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn generate_and_register_sym_key(base_url: String, auth_token: String, jwt: String, master_key: String) -> Result<KeyGenOutput, JsValue>
{
	let (key_id, key) = sentc_crypto_full::crypto::register_sym_key(base_url, auth_token.as_str(), jwt.as_str(), master_key.as_str()).await?;

	Ok(KeyGenOutput {
		key,
		key_id,
	})
}

#[wasm_bindgen]
pub async fn get_sym_key_by_id(base_url: String, auth_token: String, key_id: String, master_key: String) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::crypto::get_sym_key_by_id(base_url, auth_token.as_str(), key_id.as_str(), master_key.as_str()).await?;

	Ok(out)
}

#[wasm_bindgen]
pub struct KeysToMasterKeyFetch
{
	last_fetched_time: u128,
	last_key_id: String,
	keys: Vec<String>,
}

#[wasm_bindgen]
impl KeysToMasterKeyFetch
{
	pub fn get_keys(&self) -> JsValue
	{
		JsValue::from_serde(&self.keys).unwrap()
	}

	pub fn get_last_fetched_time(&self) -> String
	{
		self.last_fetched_time.to_string()
	}

	pub fn get_last_key_id(&self) -> String
	{
		self.last_key_id.clone()
	}
}

#[wasm_bindgen]
pub async fn get_keys_for_master_key(
	base_url: String,
	auth_token: String,
	master_key_id: String,
	last_fetched_time: String,
	last_key_id: String,
	master_key: String,
) -> Result<KeysToMasterKeyFetch, JsValue>
{
	let (keys, last_fetched_time, last_key_id) = sentc_crypto_full::crypto::get_keys_for_master_key(
		base_url,
		auth_token.as_str(),
		master_key_id.as_str(),
		last_fetched_time.as_str(),
		last_key_id.as_str(),
		master_key.as_str(),
	)
	.await?;

	Ok(KeysToMasterKeyFetch {
		last_fetched_time,
		last_key_id,
		keys,
	})
}

#[wasm_bindgen]
pub async fn delete_sym_key(base_url: String, auth_token: String, jwt: String, key_id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::crypto::delete_key(base_url, auth_token.as_str(), jwt.as_str(), key_id.as_str()).await?;

	Ok(())
}
