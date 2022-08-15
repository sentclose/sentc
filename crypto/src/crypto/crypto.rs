use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerOutput};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::SymKeyId;

use crate::crypto::{
	decrypt_asymmetric_internally,
	decrypt_raw_asymmetric_internally,
	decrypt_raw_symmetric_internally,
	decrypt_string_asymmetric_internally,
	decrypt_string_symmetric_internally,
	decrypt_sym_key_internally,
	decrypt_symmetric_internally,
	deserialize_head_from_string_internally,
	done_fetch_sym_key_internally,
	done_fetch_sym_keys_internally,
	encrypt_asymmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	encrypt_string_asymmetric_internally,
	encrypt_string_symmetric_internally,
	encrypt_symmetric_internally,
	generate_non_register_sym_key_internally,
	prepare_register_sym_key_internally,
	split_head_and_encrypted_data_internally,
	split_head_and_encrypted_string_internally,
};
use crate::util::{export_sym_key_to_string, import_private_key, import_sign_key, import_sym_key, SignKeyFormatInt};
use crate::{err_to_msg, SdkError};

fn prepare_sign_key(sign_key: &str) -> Result<Option<SignKeyFormatInt>, SdkError>
{
	let sign_key = match sign_key {
		"" => None,
		_ => {
			let k = import_sign_key(sign_key)?;

			Some(k)
		},
	};

	Ok(sign_key)
}

fn prepare_verify_key(verify_key_data: &str) -> Result<Option<UserVerifyKeyData>, SdkError>
{
	let verify_key = match verify_key_data {
		"" => None,
		_ => {
			let k = UserVerifyKeyData::from_string(verify_key_data).map_err(|_| SdkError::JsonParseFailed)?;

			Some(k)
		},
	};

	Ok(verify_key)
}

pub fn split_head_and_encrypted_data(data_with_head: &[u8]) -> Result<(EncryptedHead, &[u8]), String>
{
	Ok(split_head_and_encrypted_data_internally(data_with_head)?)
}

pub fn split_head_and_encrypted_string(data_with_head: &str) -> Result<EncryptedHead, String>
{
	Ok(split_head_and_encrypted_string_internally(data_with_head)?)
}

pub fn deserialize_head_from_string(head: &str) -> Result<EncryptedHead, String>
{
	Ok(deserialize_head_from_string_internally(head)?)
}

pub fn encrypt_raw_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<(String, Vec<u8>), String>
{
	let key = import_sym_key(key)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_raw_symmetric_internally(&key, data, Some(&k))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| err_to_msg(SdkError::JsonToStringFailed))?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let head = EncryptedHead::from_string(head).map_err(|_e| err_to_msg(SdkError::JsonParseFailed))?;

	let decrypted = match verify_key {
		None => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, None)?,
		Some(k) => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<(String, Vec<u8>), String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(SdkError::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key)?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| err_to_msg(SdkError::JsonToStringFailed))?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let private_key = import_private_key(private_key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let head = EncryptedHead::from_string(head).map_err(|_| err_to_msg(SdkError::JsonParseFailed))?;

	let decrypted = match verify_key {
		None => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, None)?,
		Some(k) => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_symmetric_internally(&key, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_symmetric_internally(&key, encrypted_data, None)?,
		Some(k) => decrypt_symmetric_internally(&key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(SdkError::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let private_key = import_private_key(private_key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_asymmetric_internally(&private_key, encrypted_data, None)?,
		Some(k) => decrypt_asymmetric_internally(&private_key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: &str) -> Result<String, String>
{
	let key = import_sym_key(key)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_string_symmetric_internally(&key, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<String, String>
{
	let key = import_sym_key(key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_string_symmetric_internally(&key, encrypted_data, None)?,
		Some(k) => decrypt_string_symmetric_internally(&key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: &str) -> Result<String, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(SdkError::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_string_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<String, String>
{
	let private_key = import_private_key(private_key)?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_string_asymmetric_internally(&private_key, encrypted_data, None)?,
		Some(k) => decrypt_string_asymmetric_internally(&private_key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn prepare_register_sym_key(master_key: &str) -> Result<String, String>
{
	let master_key = import_sym_key(master_key)?;

	let out = prepare_register_sym_key_internally(&master_key)?;

	Ok(out)
}

pub fn done_fetch_sym_key(master_key: &str, server_out: &str) -> Result<String, String>
{
	let master_key = import_sym_key(master_key)?;

	let out = done_fetch_sym_key_internally(&master_key, server_out)?;

	Ok(export_sym_key_to_string(out)?)
}

pub fn done_fetch_sym_keys(master_key: &str, server_out: &str) -> Result<(Vec<String>, u128, SymKeyId), String>
{
	let master_key = import_sym_key(master_key)?;

	let (out, last_time, last_id) = done_fetch_sym_keys_internally(&master_key, server_out)?;

	let mut out_vec = Vec::with_capacity(out.len());

	for o in out {
		out_vec.push(export_sym_key_to_string(o)?);
	}

	Ok((out_vec, last_time, last_id))
}

pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	let master_key = import_sym_key(master_key)?;
	let encrypted_symmetric_key_info =
		GeneratedSymKeyHeadServerOutput::from_string(encrypted_symmetric_key_info).map_err(|_| err_to_msg(SdkError::JsonParseFailed))?;

	let out = decrypt_sym_key_internally(&master_key, &encrypted_symmetric_key_info)?;

	Ok(export_sym_key_to_string(out)?)
}

pub fn generate_non_register_sym_key(master_key: &str) -> Result<(String, String), String>
{
	let master_key = import_sym_key(master_key)?;

	let (key, encrypted_key) = generate_non_register_sym_key_internally(&master_key)?;

	let exported_key = export_sym_key_to_string(key)?;

	let exported_encrypted_key = encrypted_key
		.to_string()
		.map_err(|_| err_to_msg(SdkError::JsonToStringFailed))?;

	Ok((exported_key, exported_encrypted_key))
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerInput;
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::SymKey;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), "").unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(user.keys.exported_public_key.as_str(), text.as_bytes(), "").unwrap();

		let decrypted = decrypt_raw_asymmetric(user.keys.private_key.as_str(), &encrypted, &head, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(
			user.keys.exported_public_key.as_str(),
			text.as_bytes(),
			user.keys.sign_key.as_str(),
		)
		.unwrap();

		let decrypted = decrypt_raw_asymmetric(
			user.keys.private_key.as_str(),
			&encrypted,
			&head,
			user.keys.exported_verify_key.as_str(),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), "").unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sig()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_asymmetric(user.keys.exported_public_key.as_str(), text.as_bytes(), "").unwrap();

		let decrypted = decrypt_asymmetric(user.keys.private_key.as_str(), &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_asymmetric(
			user.keys.exported_public_key.as_str(),
			text.as_bytes(),
			user.keys.sign_key.as_str(),
		)
		.unwrap();

		let decrypted = decrypt_asymmetric(
			user.keys.private_key.as_str(),
			&encrypted,
			user.keys.exported_verify_key.as_str(),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text, "").unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, "").unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sig()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text, user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_string_asymmetric(user.keys.exported_public_key.as_str(), text, "").unwrap();

		let decrypted = decrypt_string_asymmetric(user.keys.private_key.as_str(), &encrypted, "").unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_string_asymmetric(
			user.keys.exported_public_key.as_str(),
			text,
			user.keys.sign_key.as_str(),
		)
		.unwrap();

		let decrypted = decrypt_string_asymmetric(
			user.keys.private_key.as_str(),
			&encrypted,
			user.keys.exported_verify_key.as_str(),
		)
		.unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_key()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let master_key = &key_data[0].group_key;

		let server_in = prepare_register_sym_key(master_key).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		let server_out = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
			time: 0,
		};

		//get the key
		let decrypted_key = decrypt_sym_key(master_key, server_out.to_string().unwrap().as_str()).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_key_from_server()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let master_key = &key_data[0].group_key;

		let server_in = prepare_register_sym_key(master_key).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		let server_out = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
			time: 0,
		};

		//test server out decrypt
		let server_response = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_out),
		};

		let decrypted_key = done_fetch_sym_key(master_key, server_response.to_string().unwrap().as_str()).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_keys_as_array()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let master_key = &key_data[0].group_key;

		let server_in = prepare_register_sym_key(master_key).unwrap();
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();
		let server_out_0 = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
			time: 0,
		};

		let server_in = prepare_register_sym_key(master_key).unwrap();
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();
		let server_out_1 = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
			time: 0,
		};

		let server_outputs = vec![server_out_0, server_out_1];

		let server_response = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_outputs),
		};

		let (decrypted_keys, _, _) = done_fetch_sym_keys(master_key, server_response.to_string().unwrap().as_str()).unwrap();

		let text = "123*+^êéèüöß@€&$";

		for decrypted_key in decrypted_keys {
			let encrypted = encrypt_string_symmetric(&decrypted_key, text, user.keys.sign_key.as_str()).unwrap();

			let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

			assert_eq!(decrypted, text);
		}
	}

	#[test]
	fn test_generate_non_register_sym_key()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
		let master_key = &key_data[0].group_key;

		let (key, encrypted_key) = generate_non_register_sym_key(master_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text, user.keys.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, user.keys.exported_verify_key.as_str()).unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key(master_key, &encrypted_key).unwrap();

		let key = import_sym_key(&key).unwrap();
		let decrypted_key = import_sym_key(&decrypted_key).unwrap();

		match (key.key, decrypted_key.key) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(k1, k2);
			},
		}
	}
}
