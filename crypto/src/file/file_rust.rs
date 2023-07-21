use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::file::BelongsToType;
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_common::{FileId, FileSessionId};
use sentc_crypto_core::SymKey;
use sentc_crypto_utils::keys::{SignKeyFormatInt, SymKeyFormatInt};

use crate::file::{
	decrypt_file_part_internally,
	decrypt_file_part_start_internally,
	done_register_file_internally,
	encrypt_file_part_internally,
	encrypt_file_part_start_internally,
	prepare_file_name_update_internally,
	prepare_register_file_internally,
};
use crate::SdkError;

pub fn prepare_register_file(
	master_key_id: String,
	key: &SymKeyFormatInt,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: BelongsToType,
	file_name: Option<String>,
) -> Result<(String, Option<String>), SdkError>
{
	prepare_register_file_internally(
		master_key_id,
		key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
	)
}

pub fn done_register_file(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	done_register_file_internally(server_output)
}

pub fn prepare_file_name_update(key: &SymKeyFormatInt, file_name: Option<String>) -> Result<String, SdkError>
{
	prepare_file_name_update_internally(key, file_name)
}

pub fn encrypt_file_part_start(key: &SymKeyFormatInt, part: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<(Vec<u8>, SymKey), SdkError>
{
	encrypt_file_part_start_internally(key, part, sign_key)
}

pub fn encrypt_file_part(pre_content_key: &SymKey, part: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<(Vec<u8>, SymKey), SdkError>
{
	encrypt_file_part_internally(pre_content_key, part, sign_key)
}

pub fn decrypt_file_part_start(key: &SymKeyFormatInt, part: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<(Vec<u8>, SymKey), SdkError>
{
	decrypt_file_part_start_internally(key, part, verify_key)
}

pub fn decrypt_file_part(pre_content_key: &SymKey, part: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<(Vec<u8>, SymKey), SdkError>
{
	decrypt_file_part_internally(pre_content_key, part, verify_key)
}
