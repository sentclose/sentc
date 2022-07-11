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
	pub fn get_head(self) -> String
	{
		self.head
	}

	pub fn get_data(self) -> Vec<u8>
	{
		self.data
	}
}

#[wasm_bindgen]
pub fn encrypt_raw_symmetric(key: String, data: &[u8], sign_key: &str) -> Result<CryptoRawOutput, String>
{
	let (head, data) = crypto::encrypt_raw_symmetric(key.as_str(), data, sign_key)?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_raw_symmetric(key, encrypted_data, head, verify_key_data)
}

#[wasm_bindgen]
pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	crypto::encrypt_symmetric(key, data, sign_key)
}

#[wasm_bindgen]
pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_symmetric(key, encrypted_data, verify_key_data)
}

#[wasm_bindgen]
pub fn encrypt_string_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<String, String>
{
	crypto::encrypt_string_symmetric(key, data, sign_key)
}

#[wasm_bindgen]
pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_string_symmetric(key, encrypted_data, verify_key_data)
}

#[wasm_bindgen]
pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<CryptoRawOutput, String>
{
	let (head, data) = crypto::encrypt_raw_asymmetric(reply_public_key_data, data, sign_key)?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

#[wasm_bindgen]
pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_raw_asymmetric(private_key, encrypted_data, head, verify_key_data)
}

#[wasm_bindgen]
pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	crypto::encrypt_asymmetric(reply_public_key_data, data, sign_key)
}

#[wasm_bindgen]
pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_asymmetric(private_key, encrypted_data, verify_key_data)
}

#[wasm_bindgen]
pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<String, String>
{
	crypto::encrypt_string_asymmetric(reply_public_key_data, data, sign_key)
}

#[wasm_bindgen]
pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	crypto::decrypt_string_asymmetric(private_key, encrypted_data, verify_key_data)
}
