use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerOutput};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::Error;

use crate::crypto::{
	decrypt_asymmetric_internally,
	decrypt_raw_asymmetric_internally,
	decrypt_raw_symmetric_internally,
	decrypt_string_asymmetric_internally,
	decrypt_string_symmetric_internally,
	decrypt_sym_key_internally,
	decrypt_symmetric_internally,
	encrypt_asymmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	encrypt_string_asymmetric_internally,
	encrypt_string_symmetric_internally,
	encrypt_symmetric_internally,
	generate_non_register_sym_key_internally,
	prepare_register_sym_key_internally,
};
use crate::err_to_msg;
use crate::util::{export_sym_key_to_string, import_private_key, import_sign_key, import_sym_key, SignKeyFormatInt};

fn prepare_sign_key(sign_key: &str) -> Result<Option<SignKeyFormatInt>, Error>
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

fn prepare_verify_key(verify_key_data: &str) -> Result<Option<UserVerifyKeyData>, Error>
{
	let verify_key = match verify_key_data {
		"" => None,
		_ => {
			let k = UserVerifyKeyData::from_string(verify_key_data).map_err(|_| Error::JsonParseFailed)?;

			Some(k)
		},
	};

	Ok(verify_key)
}

pub fn encrypt_raw_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<(String, Vec<u8>), String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_symmetric_internally(&key, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_raw_symmetric_internally(&key, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| err_to_msg(Error::JsonToStringFailed))?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let head = EncryptedHead::from_string(head).map_err(|_e| err_to_msg(Error::JsonParseFailed))?;

	let decrypted = match verify_key {
		None => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<(String, Vec<u8>), String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(Error::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| err_to_msg(Error::JsonToStringFailed))?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let private_key = import_private_key(private_key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let head = EncryptedHead::from_string(head).map_err(|_| err_to_msg(Error::JsonParseFailed))?;

	let decrypted = match verify_key {
		None => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_symmetric_internally(&key, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_symmetric_internally(&key, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(encrypted)
}

pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let decrypted = match verify_key {
		None => decrypt_symmetric_internally(&key, encrypted_data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_symmetric_internally(&key, encrypted_data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<Vec<u8>, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(Error::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_asymmetric_internally(&reply_public_key_data, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_asymmetric_internally(&reply_public_key_data, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(encrypted)
}

pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let private_key = import_private_key(private_key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let decrypted = match verify_key {
		None => decrypt_asymmetric_internally(&private_key, encrypted_data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_asymmetric_internally(&private_key, encrypted_data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_symmetric(key: &str, data: &[u8], sign_key: &str) -> Result<String, String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_symmetric_internally(&key, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_string_symmetric_internally(&key, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let key = import_sym_key(key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let decrypted = match verify_key {
		None => decrypt_string_symmetric_internally(&key, encrypted_data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_string_symmetric_internally(&key, encrypted_data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: &str) -> Result<String, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(|_| err_to_msg(Error::JsonParseFailed))?;

	let sign_key = prepare_sign_key(sign_key).map_err(|e| err_to_msg(e))?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_asymmetric_internally(&reply_public_key_data, data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => encrypt_string_asymmetric_internally(&reply_public_key_data, data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: &str) -> Result<Vec<u8>, String>
{
	let private_key = import_private_key(private_key).map_err(|e| err_to_msg(e))?;

	let verify_key = prepare_verify_key(verify_key_data).map_err(|e| err_to_msg(e))?;

	let decrypted = match verify_key {
		None => decrypt_string_asymmetric_internally(&private_key, encrypted_data, None).map_err(|e| err_to_msg(e))?,
		Some(k) => decrypt_string_asymmetric_internally(&private_key, encrypted_data, Some(&k)).map_err(|e| err_to_msg(e))?,
	};

	Ok(decrypted)
}

pub fn prepare_register_sym_key(master_key: &str) -> Result<String, String>
{
	let master_key = import_sym_key(master_key).map_err(|e| err_to_msg(e))?;

	let out = prepare_register_sym_key_internally(&master_key).map_err(|e| err_to_msg(e))?;

	Ok(out)
}

pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	let master_key = import_sym_key(master_key).map_err(|e| err_to_msg(e))?;
	let encrypted_symmetric_key_info =
		GeneratedSymKeyHeadServerOutput::from_string(encrypted_symmetric_key_info).map_err(|_| err_to_msg(Error::JsonParseFailed))?;

	let out = decrypt_sym_key_internally(&master_key, &encrypted_symmetric_key_info).map_err(|e| err_to_msg(e))?;

	export_sym_key_to_string(out).map_err(|e| err_to_msg(e))
}

pub fn generate_non_register_sym_key(master_key: &str) -> Result<(String, String), String>
{
	let master_key = import_sym_key(master_key).map_err(|e| err_to_msg(e))?;

	let (key, encrypted_key) = generate_non_register_sym_key_internally(&master_key).map_err(|e| err_to_msg(e))?;

	let exported_key = export_sym_key_to_string(key).map_err(|e| err_to_msg(e))?;

	let exported_encrypted_key = encrypted_key
		.to_string()
		.map_err(|_| err_to_msg(Error::JsonToStringFailed))?;

	Ok((exported_key, exported_encrypted_key))
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;

	use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerInput;
	use sentc_crypto_core::SymKey;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();
		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), "").unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		let user = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), "").unwrap();

		let decrypted = decrypt_raw_asymmetric(user.private_key.as_str(), &encrypted, &head, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_raw_asymmetric(user.private_key.as_str(), &encrypted, &head, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym()
	{
		let user = create_user();
		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), "").unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sig()
	{
		let user = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), "").unwrap();

		let decrypted = decrypt_asymmetric(user.private_key.as_str(), &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_asymmetric(user.private_key.as_str(), &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let user = create_user();
		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text.as_bytes(), "").unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sig()
	{
		let user = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_string_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), "").unwrap();

		let decrypted = decrypt_string_asymmetric(user.private_key.as_str(), &encrypted, "").unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let encrypted = encrypt_string_asymmetric(user.exported_public_key.as_str(), text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_asymmetric(user.private_key.as_str(), &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_key()
	{
		let user = create_user();
		let (group, _) = create_group(&user);
		let master_key = &group.keys[0].group_key;

		let server_in = prepare_register_sym_key(master_key).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		let server_out = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
		};

		//get the key
		let decrypted_key = decrypt_sym_key(master_key, server_out.to_string().unwrap().as_str()).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(decrypted, text.as_bytes())
	}

	#[test]
	fn test_generate_non_register_sym_key()
	{
		let user = create_user();
		let (group, _) = create_group(&user);
		let master_key = &group.keys[0].group_key;

		let (key, encrypted_key) = generate_non_register_sym_key(master_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text.as_bytes(), user.sign_key.as_str()).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, user.exported_verify_key.as_str()).unwrap();

		assert_eq!(decrypted, text.as_bytes());

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
