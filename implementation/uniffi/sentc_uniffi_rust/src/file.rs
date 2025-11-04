use sentc_crypto::util_req_full;

use crate::SentcError;

#[derive(uniffi::Enum)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_download_file_meta(
	base_url: String,
	auth_token: &str,
	jwt: Option<String>,
	id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<FileData, SentcError>
{
	let out = util_req_full::file::download_file_meta(
		base_url,
		auth_token,
		id,
		jwt.as_deref(),
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into())
}

#[derive(uniffi::Record)]
pub struct FileDownloadResult
{
	pub next_file_key: String,
	pub file: Vec<u8>,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	content_key: &str,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult, SentcError>
{
	let (file, next_file_key) = util_req_full::file::download_and_decrypt_file_part_start(
		base_url,
		url_prefix,
		auth_token,
		part_id,
		content_key,
		verify_key_data.as_deref(),
	)
	.await?;

	Ok(FileDownloadResult {
		next_file_key,
		file,
	})
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_download_and_decrypt_file_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	content_key: &str,
	verify_key_data: Option<String>,
) -> Result<FileDownloadResult, SentcError>
{
	let (file, next_file_key) = util_req_full::file::download_and_decrypt_file_part(
		base_url,
		url_prefix,
		auth_token,
		part_id,
		content_key,
		verify_key_data.as_deref(),
	)
	.await?;

	Ok(FileDownloadResult {
		next_file_key,
		file,
	})
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_download_part_list(
	base_url: String,
	auth_token: &str,
	file_id: &str,
	last_sequence: &str,
) -> Result<Vec<FilePartListItem>, SentcError>
{
	let out = util_req_full::file::download_part_list(base_url, auth_token, file_id, last_sequence).await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________

#[derive(uniffi::Record)]
pub struct FileRegisterOutput
{
	pub file_id: String,
	pub session_id: String,
	pub encrypted_file_name: Option<String>,
}

#[derive(uniffi::Record)]
pub struct FilePrepareRegister
{
	pub encrypted_file_name: Option<String>,
	pub server_input: String,
}

#[derive(uniffi::Record)]
pub struct FileDoneRegister
{
	pub file_id: String,
	pub session_id: String,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_register_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	master_key_id: String,
	content_key: &str,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: &str,
	file_name: Option<String>,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<FileRegisterOutput, SentcError>
{
	let (file_id, session_id, encrypted_file_name) = util_req_full::file::register_file(
		base_url,
		auth_token,
		jwt,
		master_key_id,
		content_key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
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

#[uniffi::export]
pub fn file_prepare_register_file(
	master_key_id: String,
	content_key: &str,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: &str,
	file_name: Option<String>,
) -> Result<FilePrepareRegister, SentcError>
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

#[uniffi::export]
pub fn file_done_register_file(server_output: String) -> Result<FileDoneRegister, SentcError>
{
	let (file_id, session_id) = sentc_crypto::file::done_register_file(&server_output)?;

	Ok(FileDoneRegister {
		file_id,
		session_id,
	})
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_upload_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence_: i32,
	content_key: &str,
	sign_key: Option<String>,
	part: Vec<u8>,
) -> Result<String, SentcError>
{
	Ok(util_req_full::file::upload_part_start(
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence_,
		content_key,
		sign_key.as_deref(),
		&part,
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_upload_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence_: i32,
	content_key: &str,
	sign_key: Option<String>,
	part: Vec<u8>,
) -> Result<String, SentcError>
{
	Ok(util_req_full::file::upload_part(
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence_,
		content_key,
		sign_key.as_deref(),
		&part,
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_file_name_update(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	file_id: &str,
	content_key: &str,
	file_name: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::file::update_file_name(base_url, auth_token, jwt, file_id, content_key, file_name).await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn file_delete_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	file_id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::file::delete_file(
		base_url,
		auth_token,
		jwt,
		file_id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?)
}
