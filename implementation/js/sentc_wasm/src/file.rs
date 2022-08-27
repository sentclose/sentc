use alloc::string::String;
use alloc::vec::Vec;

use js_sys::Uint8Array;
use sentc_crypto_common::file::BelongsToType;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FileData
{
	file_id: String,
	belongs_to: Option<String>,
	belongs_to_type: BelongsToType,
	key_id: String,
	part_list: Vec<String>,
}

impl From<sentc_crypto_common::file::FileData> for FileData
{
	fn from(data: sentc_crypto_common::file::FileData) -> Self
	{
		Self {
			file_id: data.file_id,
			belongs_to: data.belongs_to,
			belongs_to_type: data.belongs_to_type,
			key_id: data.key_id,
			part_list: data.part_list,
		}
	}
}

#[wasm_bindgen]
impl FileData
{
	pub fn get_key_id(&self) -> String
	{
		self.key_id.clone()
	}

	pub fn get_part_list(&self) -> JsValue
	{
		JsValue::from_serde(&self.part_list).unwrap()
	}

	pub fn get_belongs_to(&self) -> Option<String>
	{
		self.belongs_to.clone()
	}

	pub fn get_belongs_to_type(&self) -> JsValue
	{
		JsValue::from_serde(&self.belongs_to_type).unwrap()
	}

	pub fn get_file_id(&self) -> String
	{
		self.file_id.clone()
	}
}

#[wasm_bindgen]
pub async fn file_download_file_meta(base_url: String, auth_token: String, jwt: String, id: String) -> Result<FileData, JsValue>
{
	let out = sentc_crypto_full::file::download_file_meta(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn file_download_and_decrypt_file_part(
	base_url: String,
	auth_token: String,
	jwt: String,
	part_id: String,
	content_key: String,
	verify_key_data: String,
) -> Result<Uint8Array, JsValue>
{
	let out = sentc_crypto_full::file::download_and_decrypt_file_part(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_str(),
	)
	.await?;

	//fastest way to convert vec to Uint8Array
	Ok(unsafe { Uint8Array::view(&out) })
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn file_register_file(base_url: String, auth_token: String, jwt: String, content_key: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::file::register_file(base_url, auth_token.as_str(), jwt.as_str(), content_key.as_str()).await?)
}

#[wasm_bindgen]
pub async fn file_upload_part(
	base_url: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	content_key: String,
	sign_key: String,
	part: Vec<u8>,
) -> Result<(), JsValue>
{
	sentc_crypto_full::file::upload_part(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		&part,
		content_key.as_str(),
		sign_key.as_str(),
	)
	.await?;

	Ok(())
}
