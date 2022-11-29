use alloc::string::String;
use alloc::vec::Vec;

use js_sys::Uint8Array;
use sentc_crypto_common::file::{BelongsToType, FilePartListItem};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FileData
{
	file_id: String,
	master_key_id: String,
	belongs_to: Option<String>,
	belongs_to_type: BelongsToType,
	key_id: String,
	part_list: Vec<FilePartListItem>,
	encrypted_file_name: Option<String>,
}

impl From<sentc_crypto_common::file::FileData> for FileData
{
	fn from(data: sentc_crypto_common::file::FileData) -> Self
	{
		Self {
			file_id: data.file_id,
			master_key_id: data.master_key_id,
			belongs_to: data.belongs_to,
			belongs_to_type: data.belongs_to_type,
			key_id: data.key_id,
			part_list: data.part_list,
			encrypted_file_name: data.encrypted_file_name,
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

	pub fn get_master_key_id(&self) -> String
	{
		self.master_key_id.clone()
	}

	pub fn get_part_list(&self) -> JsValue
	{
		JsValue::from_serde(&self.part_list).unwrap()
	}

	pub fn get_belongs_to(&self) -> Option<String>
	{
		self.belongs_to.clone()
	}

	pub fn get_encrypted_file_name(&self) -> Option<String>
	{
		self.encrypted_file_name.clone()
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
pub struct FilePrepareRegister
{
	encrypted_file_name: String,
	server_input: String,
}

#[wasm_bindgen]
impl FilePrepareRegister
{
	pub fn get_encrypted_file_name(&self) -> String
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
	encrypted_file_name: String,
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

	pub fn get_encrypted_file_name(&self) -> String
	{
		self.encrypted_file_name.clone()
	}
}

#[wasm_bindgen]
pub async fn file_download_file_meta(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: String,
) -> Result<FileData, JsValue>
{
	let group_as_member = if group_as_member.is_empty() {
		None
	} else {
		Some(group_as_member.as_str())
	};

	let out = sentc_crypto_full::file::download_file_meta(
		base_url,
		auth_token.as_str(),
		id.as_str(),
		jwt.as_str(),
		group_id.as_str(),
		group_as_member,
	)
	.await?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn file_download_and_decrypt_file_part(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: String,
) -> Result<Uint8Array, JsValue>
{
	let out = sentc_crypto_full::file::download_and_decrypt_file_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_str(),
	)
	.await?;

	//fastest way to convert vec to Uint8Array
	Ok(unsafe { Uint8Array::view(&out) })
}

#[wasm_bindgen]
pub async fn file_download_part_list(base_url: String, auth_token: String, file_id: String, last_sequence: String) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::file::download_part_list(
		base_url,
		auth_token.as_str(),
		file_id.as_str(),
		last_sequence.as_str(),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn file_register_file(
	base_url: String,
	auth_token: String,
	jwt: String,
	master_key_id: String,
	content_key: String,
	belongs_to_id: String,
	belongs_to_type: String,
	file_name: String,
	group_id: String,
	group_as_member: String,
) -> Result<FileRegisterOutput, JsValue>
{
	let group_as_member = if group_as_member.is_empty() {
		None
	} else {
		Some(group_as_member.as_str())
	};

	let (file_id, session_id, encrypted_file_name) = sentc_crypto_full::file::register_file(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		master_key_id,
		content_key.as_str(),
		belongs_to_id.as_str(),
		belongs_to_type.as_str(),
		file_name.as_str(),
		group_id.as_str(),
		group_as_member,
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
	belongs_to_id: &str,
	belongs_to_type: &str,
	file_name: &str,
) -> Result<FilePrepareRegister, JsValue>
{
	let (input, encrypted_file_name) =
		sentc_crypto::file::prepare_register_file(master_key_id, content_key, belongs_to_id, belongs_to_type, file_name)?;

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
pub async fn file_upload_part(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	sequence: i32,
	content_key: String,
	sign_key: String,
	part: Vec<u8>,
) -> Result<(), JsValue>
{
	sentc_crypto_full::file::upload_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		sequence,
		content_key.as_str(),
		sign_key.as_str(),
		&part,
	)
	.await?;

	Ok(())
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

#[wasm_bindgen]
pub async fn file_delete_file(
	base_url: String,
	auth_token: String,
	jwt: String,
	file_id: String,
	group_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	let group_as_member = if group_as_member.is_empty() {
		None
	} else {
		Some(group_as_member.as_str())
	};

	sentc_crypto_full::file::delete_file(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		file_id.as_str(),
		group_id.as_str(),
		group_as_member,
	)
	.await?;

	Ok(())
}
