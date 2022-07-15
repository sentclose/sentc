use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::crypto;
use wasm_bindgen::prelude::*;
use web_sys::{RequestInit, RequestMode};

use crate::make_req;

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

#[wasm_bindgen]
pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	crypto::decrypt_sym_key(master_key, encrypted_symmetric_key_info)
}

#[wasm_bindgen]
pub async fn generate_and_register_sym_key(base_url: String, auth_token: String, master_key: String) -> Result<String, JsValue>
{
	let server_in = crypto::prepare_register_sym_key(master_key.as_str())?;

	let url = format!("{}/api/v1/key/register", base_url);

	let mut opts = RequestInit::new();
	opts.method("POST");
	opts.mode(RequestMode::NoCors);
	opts.body(Some(&JsValue::from_str(server_in.as_str())));

	//should return the generated server key output
	let res = make_req(url.as_str(), auth_token.as_str(), &opts).await?;

	Ok(decrypt_sym_key(master_key.as_str(), res.as_str())?)
}
