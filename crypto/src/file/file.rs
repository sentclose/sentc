use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::file::{BelongsToType, FileHead, FileNameUpdate, FileRegisterInput, FileRegisterOutput};
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_common::{FileId, FileSessionId};
use sentc_crypto_core::cryptomat::{CryptoAlg, SymKey, SymKeyComposer, SymKeyGen};
use sentc_crypto_core::{Signature, SymmetricKey as CoreSymmetricKey};

use crate::crypto::{put_head_and_encrypted_data_internally, sign_internally, split_head_and_encrypted_data_internally, verify_internally};
use crate::entities::keys::{SignKey, SymmetricKey};
use crate::util::public::handle_server_response;
use crate::{crypto, SdkError};

pub fn prepare_register_file(
	master_key_id: String,
	key: &SymmetricKey,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: BelongsToType,
	file_name: Option<String>,
) -> Result<(String, Option<String>), SdkError>
{
	let encrypted_key_alg = &key.key.get_alg_str();

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
			encrypted_key: encrypted_content_key,
			belongs_to_id,
			belongs_to_type,
			encrypted_file_name: encrypted_file_name.clone(),
			encrypted_key_alg: encrypted_key_alg.to_string(),
		})
		.map_err(|_e| SdkError::JsonToStringFailed)?,
		encrypted_file_name,
	))
}

pub fn done_register_file(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	let out: FileRegisterOutput = handle_server_response(server_output)?;

	Ok((out.file_id, out.session_id))
}

pub fn prepare_file_name_update(key: &SymmetricKey, file_name: Option<String>) -> Result<String, SdkError>
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
pub fn encrypt_file_part_start(key: &SymmetricKey, part: &[u8], sign_key: Option<&SignKey>) -> Result<(Vec<u8>, impl SymKey), SdkError>
{
	encrypt_file_part(&key.key, part, sign_key)
}

pub fn encrypt_file_part(pre_content_key: &impl SymKey, part: &[u8], sign_key: Option<&SignKey>) -> Result<(Vec<u8>, impl SymKey), SdkError>
{
	/*
	Just create a normal core key without id
	 */
	let (encrypted_key, file_key) = CoreSymmetricKey::generate_symmetric_with_sym_key(pre_content_key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let mut encrypted_part = file_key.encrypt(part)?;

	//sign the data
	let sign = if let Some(sk) = sign_key {
		let (sign_head, data_with_sign) = sign_internally(sk, &encrypted_part)?;
		encrypted_part = data_with_sign;
		Some(sign_head)
	} else {
		None
	};

	//set here the file key (encrypted by the content key which is the key of the previous part or the initial file key
	let file_head = FileHead {
		key: encrypted_key_string,
		sign,
		sym_key_alg: file_key.get_alg_str().to_string(),
	};

	Ok((
		put_head_and_encrypted_data_internally(&file_head, &encrypted_part)?,
		file_key,
	))
}

pub fn decrypt_file_part_start(key: &SymmetricKey, part: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<(Vec<u8>, impl SymKey), SdkError>
{
	decrypt_file_part(&key.key, part, verify_key)
}

pub fn decrypt_file_part(
	pre_content_key: &impl SymKey,
	part: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<(Vec<u8>, impl SymKey), SdkError>
{
	let (head, encrypted_part) = split_head_and_encrypted_data_internally::<FileHead>(part)?;

	//decrypt the key with the pre key
	let encrypted_key = Base64::decode_vec(&head.key).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let file_key = CoreSymmetricKey::decrypt_key_by_sym_key(pre_content_key, &encrypted_key, &head.sym_key_alg)?;

	let decrypted_part = match &head.sign {
		None => file_key.decrypt(encrypted_part)?, //no sig used, go ahead
		Some(h) => {
			match verify_key {
				None => {
					//just split the data, use the alg here
					let (_, encrypted_data_without_sig) = Signature::split_sig_and_data(h.alg.as_str(), encrypted_part)?;
					file_key.decrypt(encrypted_data_without_sig)?
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(vk, encrypted_part, h)?;
					file_key.decrypt(encrypted_data_without_sig)?
				},
			}
		},
	};

	Ok((decrypted_part, file_key))
}
