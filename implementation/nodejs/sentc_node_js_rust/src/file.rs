use napi::bindgen_prelude::*;
use sentc_crypto::util_req_full;

#[napi]
pub enum BelongsToType
{
	Group,
	User,
	None,
}

impl From<sentc_crypto_common::file::BelongsToType> for BelongsToType
{
	fn from(t: sentc_crypto_common::file::BelongsToType) -> Self
	{
		match t {
			sentc_crypto_common::file::BelongsToType::None => Self::None,
			sentc_crypto_common::file::BelongsToType::Group => Self::Group,
			sentc_crypto_common::file::BelongsToType::User => Self::User,
		}
	}
}

#[napi(object)]
pub struct FilePartListItem
{
	pub part_id: String,
	pub sequence: i32,
	pub extern_storage: bool,
}

impl From<sentc_crypto_common::file::FilePartListItem> for FilePartListItem
{
	fn from(item: sentc_crypto_common::file::FilePartListItem) -> Self
	{
		Self {
			part_id: item.part_id,
			sequence: item.sequence,
			extern_storage: item.extern_storage,
		}
	}
}

#[napi(object)]
pub struct FileData
{
	pub file_id: String,
	pub master_key_id: String,
	pub owner: String,
	pub belongs_to: Option<String>, //can be a group or a user. if belongs to type is none, then this is Option::None
	pub belongs_to_type: BelongsToType,
	pub encrypted_key: String,
	pub encrypted_key_alg: String,
	pub encrypted_file_name: Option<String>,
	pub part_list: Vec<FilePartListItem>,
}

impl From<sentc_crypto_common::file::FileData> for FileData
{
	fn from(data: sentc_crypto_common::file::FileData) -> Self
	{
		Self {
			file_id: data.file_id,
			master_key_id: data.master_key_id,
			owner: data.owner,
			belongs_to: data.belongs_to,
			belongs_to_type: data.belongs_to_type.into(),
			encrypted_key: data.encrypted_key,
			encrypted_key_alg: data.encrypted_key_alg,
			encrypted_file_name: data.encrypted_file_name,
			part_list: data.part_list.into_iter().map(|part| part.into()).collect(),
		}
	}
}

#[napi]
pub async fn file_download_file_meta(
	base_url: String,
	auth_token: String,
	jwt: Option<String>,
	id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<FileData>
{
	let out = util_req_full::file::download_file_meta(
		base_url,
		&auth_token,
		&id,
		jwt.as_deref(),
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi(object)]
pub struct FileDownloadResult
{
	pub next_file_key: String,
	pub file: Buffer,
}

#[napi]
pub async fn file_download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult>
{
	let (file, next_file_key) = util_req_full::file::download_and_decrypt_file_part_start(
		base_url,
		url_prefix,
		&auth_token,
		&part_id,
		&content_key,
		verify_key_data.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(FileDownloadResult {
		next_file_key,
		file: file.into(),
	})
}

#[napi]
pub async fn file_download_and_decrypt_file_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult>
{
	let (file, next_file_key) = util_req_full::file::download_and_decrypt_file_part(
		base_url,
		url_prefix,
		&auth_token,
		&part_id,
		&content_key,
		verify_key_data.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(FileDownloadResult {
		next_file_key,
		file: file.into(),
	})
}

#[napi]
pub async fn file_download_part_list(base_url: String, auth_token: String, file_id: String, last_sequence: String) -> Result<Vec<FilePartListItem>>
{
	let out = util_req_full::file::download_part_list(base_url, &auth_token, &file_id, &last_sequence)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct FileRegisterOutput
{
	pub file_id: String,
	pub session_id: String,
	pub encrypted_file_name: Option<String>,
}

#[napi(object)]
pub struct FilePrepareRegister
{
	pub encrypted_file_name: Option<String>,
	pub server_input: String,
}

#[napi(object)]
pub struct FileDoneRegister
{
	pub file_id: String,
	pub session_id: String,
}

#[napi]
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
) -> Result<FileRegisterOutput>
{
	let (file_id, session_id, encrypted_file_name) = util_req_full::file::register_file(
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
	.await
	.map_err(Error::from_reason)?;

	Ok(FileRegisterOutput {
		file_id,
		session_id,
		encrypted_file_name,
	})
}

#[napi]
pub fn file_prepare_register_file(
	master_key_id: String,
	content_key: String,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: String,
	file_name: Option<String>,
) -> Result<FilePrepareRegister>
{
	let (input, encrypted_file_name) = sentc_crypto::file::prepare_register_file(
		master_key_id,
		&content_key,
		encrypted_content_key,
		belongs_to_id,
		&belongs_to_type,
		file_name,
	)
	.map_err(Error::from_reason)?;

	Ok(FilePrepareRegister {
		encrypted_file_name,
		server_input: input,
	})
}

#[napi]
pub fn file_done_register_file(server_output: String) -> Result<FileDoneRegister>
{
	let (file_id, session_id) = sentc_crypto::file::done_register_file(&server_output).map_err(Error::from_reason)?;

	Ok(FileDoneRegister {
		file_id,
		session_id,
	})
}

#[napi]
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
	part: Buffer,
) -> Result<String>
{
	util_req_full::file::upload_part_start(
		base_url,
		url_prefix,
		&auth_token,
		&jwt,
		&session_id,
		end,
		sequence,
		&content_key,
		sign_key.as_deref(),
		&part,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
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
	part: Buffer,
) -> Result<String>
{
	util_req_full::file::upload_part(
		base_url,
		url_prefix,
		&auth_token,
		&jwt,
		&session_id,
		end,
		sequence,
		&content_key,
		sign_key.as_deref(),
		&part,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn file_file_name_update(
	base_url: String,
	auth_token: String,
	jwt: String,
	file_id: String,
	content_key: String,
	file_name: Option<String>,
) -> Result<()>
{
	util_req_full::file::update_file_name(base_url, &auth_token, &jwt, &file_id, &content_key, file_name)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn file_delete_file(
	base_url: String,
	auth_token: String,
	jwt: String,
	file_id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::file::delete_file(
		base_url,
		&auth_token,
		&jwt,
		&file_id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}
