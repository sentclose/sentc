use alloc::string::String;
use alloc::vec::Vec;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FilePrepareRegister
{
	encrypted_file_name: Option<String>,
	server_input: String,
}

#[wasm_bindgen]
impl FilePrepareRegister
{
	pub fn get_encrypted_file_name(&self) -> Option<String>
	{
		self.encrypted_file_name.clone()
	}

	pub fn get_server_input(&self) -> String
	{
		self.server_input.clone()
	}
}

#[wasm_bindgen]
pub struct FileDoneRegister
{
	file_id: String,
	session_id: String,
}

#[wasm_bindgen]
impl FileDoneRegister
{
	pub fn get_file_id(&self) -> String
	{
		self.file_id.clone()
	}

	pub fn get_session_id(&self) -> String
	{
		self.session_id.clone()
	}
}

#[wasm_bindgen]
pub struct FileRegisterOutput
{
	file_id: String,
	session_id: String,
	encrypted_file_name: Option<String>,
}

#[wasm_bindgen]
impl FileRegisterOutput
{
	pub fn get_file_id(&self) -> String
	{
		self.file_id.clone()
	}

	pub fn get_session_id(&self) -> String
	{
		self.session_id.clone()
	}

	pub fn get_encrypted_file_name(&self) -> Option<String>
	{
		self.encrypted_file_name.clone()
	}
}

#[wasm_bindgen]
pub struct FileDownloadResult
{
	next_file_key: String,
	file: Vec<u8>,
}

#[wasm_bindgen]
impl FileDownloadResult
{
	pub fn get_next_file_key(&self) -> String
	{
		self.next_file_key.clone()
	}

	pub fn get_file(&self) -> Uint8Array
	{
		//fastest way to convert vec to Uint8Array
		unsafe { Uint8Array::view(&self.file) }
	}
}

#[wasm_bindgen]
pub async fn file_download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult, JsValue>
{
	let (file, next_file_key) = sentc_crypto_full::file::download_and_decrypt_file_part_start(
		base_url,
		url_prefix,
		auth_token.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_deref(),
	)
	.await?;

	//fastest way to convert vec to Uint8Array
	Ok(FileDownloadResult {
		next_file_key,
		file,
	})
}

#[wasm_bindgen]
pub async fn file_download_and_decrypt_file_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult, JsValue>
{
	let (file, next_file_key) = sentc_crypto_full::file::download_and_decrypt_file_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_deref(),
	)
	.await?;

	//fastest way to convert vec to Uint8Array
	Ok(FileDownloadResult {
		next_file_key,
		file,
	})
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn file_register_file(
	base_url: String,
	auth_token: String,
	jwt: String,
	master_key_id: String,
	content_key: String,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: String,
	file_name: Option<String>,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<FileRegisterOutput, JsValue>
{
	let (file_id, session_id, encrypted_file_name) = sentc_crypto_full::file::register_file(
		base_url,
		&auth_token,
		&jwt,
		master_key_id,
		&content_key,
		encrypted_content_key,
		belongs_to_id,
		&belongs_to_type,
		file_name,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?;

	Ok(FileRegisterOutput {
		file_id,
		session_id,
		encrypted_file_name,
	})
}

#[wasm_bindgen]
pub fn file_prepare_register_file(
	master_key_id: String,
	content_key: &str,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: &str,
	file_name: Option<String>,
) -> Result<FilePrepareRegister, JsValue>
{
	let (input, encrypted_file_name) = sentc_crypto::file::prepare_register_file(
		master_key_id,
		content_key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
	)?;

	Ok(FilePrepareRegister {
		encrypted_file_name,
		server_input: input,
	})
}

#[wasm_bindgen]
pub fn file_done_register_file(server_output: &str) -> Result<FileDoneRegister, JsValue>
{
	let (file_id, session_id) = sentc_crypto::file::done_register_file(server_output)?;

	Ok(FileDoneRegister {
		file_id,
		session_id,
	})
}

#[wasm_bindgen]
pub async fn file_upload_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	sequence: i32,
	content_key: String,
	sign_key: Option<String>,
	part: Vec<u8>,
) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::file::upload_part_start(
		base_url,
		url_prefix,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		sequence,
		content_key.as_str(),
		sign_key.as_deref(),
		&part,
	)
	.await?)
}

#[wasm_bindgen]
pub async fn file_upload_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	sequence: i32,
	content_key: String,
	sign_key: Option<String>,
	part: Vec<u8>,
) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::file::upload_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		sequence,
		content_key.as_str(),
		sign_key.as_deref(),
		&part,
	)
	.await?)
}

#[wasm_bindgen]
pub async fn file_file_name_update(
	base_url: String,
	auth_token: String,
	jwt: String,
	file_id: String,
	content_key: String,
	file_name: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::file::update_file_name(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		file_id.as_str(),
		content_key.as_str(),
		file_name.as_str(),
	)
	.await?;

	Ok(())
}
