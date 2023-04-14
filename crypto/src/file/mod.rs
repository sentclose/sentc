#[cfg(not(feature = "rust"))]
mod file;
#[cfg(feature = "rust")]
mod file_rust;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::file::{BelongsToType, FileHead, FileNameUpdate, FileRegisterInput, FileRegisterOutput};
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_common::{FileId, FileSessionId};
use sentc_crypto_core::SymKey;

#[cfg(not(feature = "rust"))]
pub use self::file::{
	decrypt_file_part,
	decrypt_file_part_start,
	done_register_file,
	encrypt_file_part,
	encrypt_file_part_start,
	prepare_file_name_update,
	prepare_register_file,
};
#[cfg(feature = "rust")]
pub use self::file_rust::{
	decrypt_file_part,
	decrypt_file_part_start,
	done_register_file,
	encrypt_file_part,
	encrypt_file_part_start,
	prepare_file_name_update,
	prepare_register_file,
};
use crate::crypto::{put_head_and_encrypted_data_internally, sign_internally, split_head_and_encrypted_data_internally, verify_internally};
use crate::util::public::handle_server_response;
use crate::util::{SignKeyFormatInt, SymKeyFormatInt};
use crate::{crypto, SdkError};

fn prepare_register_file_internally(
	master_key_id: String,
	key: &SymKeyFormatInt,
	belongs_to_id: Option<String>,
	belongs_to_type: BelongsToType,
	file_name: Option<String>,
) -> Result<(String, Option<String>), SdkError>
{
	let key_id = key.key_id.clone();

	// this check is already done in the backend too
	let (belongs_to_type, belongs_to_id) = match belongs_to_type {
		BelongsToType::None => (belongs_to_type, None),
		_ => {
			//check if the id is set

			if belongs_to_id.is_none() {
				(BelongsToType::None, None)
			} else {
				(belongs_to_type, belongs_to_id)
			}
		},
	};

	let encrypted_file_name = match file_name {
		None => None,
		Some(f) => {
			//encrypt the filename with the sym key
			Some(crypto::encrypt_string_symmetric_internally(key, &f, None)?)
		},
	};

	Ok((
		serde_json::to_string(&FileRegisterInput {
			master_key_id,
			key_id,
			belongs_to_id,
			belongs_to_type,
			encrypted_file_name: encrypted_file_name.clone(),
		})
		.map_err(|_e| SdkError::JsonToStringFailed)?,
		encrypted_file_name,
	))
}

fn done_register_file_internally(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	let out: FileRegisterOutput = handle_server_response(server_output)?;

	Ok((out.file_id, out.session_id))
}

fn prepare_file_name_update_internally(key: &SymKeyFormatInt, file_name: Option<String>) -> Result<String, SdkError>
{
	let encrypted_file_name = match file_name {
		None => None,
		Some(f) => {
			//encrypt the filename with the sym key
			Some(crypto::encrypt_string_symmetric_internally(key, &f, None)?)
		},
	};

	serde_json::to_string(&FileNameUpdate {
		encrypted_file_name,
	})
	.map_err(|_e| SdkError::JsonToStringFailed)
}

/**
The first part is encrypted by the file initial key. This key id is stored in the file data and must not be in every file head
*/
fn encrypt_file_part_start_internally(key: &SymKeyFormatInt, part: &[u8], sign_key: Option<&SignKeyFormatInt>)
	-> Result<(Vec<u8>, SymKey), SdkError>
{
	encrypt_file_part_internally(&key.key, part, sign_key)
}

fn encrypt_file_part_internally(pre_content_key: &SymKey, part: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<(Vec<u8>, SymKey), SdkError>
{
	/*
	Just create a normal core key without id
	 */
	let (encrypted_key, sym_key_alg, file_key) = sentc_crypto_core::crypto::generate_symmetric_with_master_key(pre_content_key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let mut encrypted_part = sentc_crypto_core::crypto::encrypt_symmetric(&file_key, part)?;

	//sign the data
	let sign = if let Some(sk) = sign_key {
		let (sign_head, data_with_sign) = sign_internally(sk, &encrypted_part)?;
		encrypted_part = data_with_sign;
		sign_head
	} else {
		None
	};

	//set here the file key (encrypted by the content key which is the key of the previous part or the initial file key
	let file_head = FileHead {
		key: encrypted_key_string,
		sign,
		sym_key_alg: sym_key_alg.to_string(),
	};

	Ok((
		put_head_and_encrypted_data_internally(&file_head, &encrypted_part)?,
		file_key,
	))
}

fn decrypt_file_part_start_internally(
	key: &SymKeyFormatInt,
	part: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<(Vec<u8>, SymKey), SdkError>
{
	decrypt_file_part_internally(&key.key, part, verify_key)
}

fn decrypt_file_part_internally(pre_content_key: &SymKey, part: &[u8], verify_key: Option<&UserVerifyKeyData>)
	-> Result<(Vec<u8>, SymKey), SdkError>
{
	let (head, encrypted_part) = split_head_and_encrypted_data_internally::<FileHead>(part)?;

	//decrypt the key with the pre key
	let encrypted_key = Base64::decode_vec(&head.key).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let file_key = sentc_crypto_core::crypto::get_symmetric_key_from_master_key(pre_content_key, &encrypted_key, &head.sym_key_alg)?;

	let decrypted_part = match &head.sign {
		None => sentc_crypto_core::crypto::decrypt_symmetric(&file_key, encrypted_part)?, //no sig used, go ahead
		Some(h) => {
			match verify_key {
				None => {
					//just split the data, use the alg here
					let (_, encrypted_data_without_sig) = sentc_crypto_core::crypto::split_sig_and_data(h.alg.as_str(), encrypted_part)?;
					sentc_crypto_core::crypto::decrypt_symmetric(&file_key, encrypted_data_without_sig)?
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(vk, encrypted_part, h)?;
					sentc_crypto_core::crypto::decrypt_symmetric(&file_key, encrypted_data_without_sig)?
				},
			}
		},
	};

	Ok((decrypted_part, file_key))
}
