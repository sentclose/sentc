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
pub fn encrypt_raw_symmetric(key: String, data: &[u8]) -> Result<CryptoRawOutput, String>
{
	let (head, data) = crypto::encrypt_raw_symmetric(key.as_str(), data, "")?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}
