use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerOutput};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::SymKeyId;
use sentc_crypto_utils::keys::SignKeyFormatInt;

use crate::crypto::{
	decrypt_asymmetric_internally,
	decrypt_raw_asymmetric_internally,
	decrypt_raw_symmetric_internally,
	decrypt_raw_symmetric_with_aad_internally,
	decrypt_string_asymmetric_internally,
	decrypt_string_symmetric_internally,
	decrypt_sym_key_by_private_key_internally,
	decrypt_sym_key_internally,
	decrypt_symmetric_internally,
	deserialize_head_from_string_internally,
	done_fetch_sym_key_by_private_key_internally,
	done_fetch_sym_key_internally,
	done_fetch_sym_keys_internally,
	done_register_sym_key_internally,
	encrypt_asymmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	encrypt_raw_symmetric_with_aad_internally,
	encrypt_string_asymmetric_internally,
	encrypt_string_symmetric_internally,
	encrypt_symmetric_internally,
	generate_non_register_sym_key_by_public_key_internally,
	generate_non_register_sym_key_internally,
	prepare_register_sym_key_by_public_key_internally,
	prepare_register_sym_key_internally,
	split_head_and_encrypted_data_internally,
	split_head_and_encrypted_string_internally,
};
use crate::SdkError;

pub(crate) fn prepare_sign_key(sign_key: Option<&str>) -> Result<Option<SignKeyFormatInt>, SdkError>
{
	let sign_key = match sign_key {
		None => None,
		Some(k) => Some(k.parse()?),
	};

	Ok(sign_key)
}

pub(crate) fn prepare_verify_key(verify_key_data: Option<&str>) -> Result<Option<UserVerifyKeyData>, SdkError>
{
	let verify_key = match verify_key_data {
		None => None,
		Some(k) => {
			let k = UserVerifyKeyData::from_string(k)?;

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

pub fn encrypt_raw_symmetric(key: &str, data: &[u8], sign_key: Option<&str>) -> Result<(String, Vec<u8>), String>
{
	let key = key.parse()?;

	let sign_key = prepare_sign_key(sign_key)?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_raw_symmetric_internally(&key, data, Some(&k))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| SdkError::JsonToStringFailed)?;

	Ok((head, encrypted))
}

pub fn encrypt_raw_symmetric_with_aad(key: &str, data: &[u8], aad: &[u8], sign_key: Option<&str>) -> Result<(String, Vec<u8>), String>
{
	let key = key.parse()?;

	let sign_key = prepare_sign_key(sign_key)?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_symmetric_with_aad_internally(&key, data, aad, None)?,
		Some(k) => encrypt_raw_symmetric_with_aad_internally(&key, data, aad, Some(&k))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| SdkError::JsonToStringFailed)?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_symmetric(key: &str, encrypted_data: &[u8], head: &str, verify_key_data: Option<&str>) -> Result<Vec<u8>, String>
{
	let key = key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let head = EncryptedHead::from_string(head).map_err(SdkError::JsonParseFailed)?;

	let decrypted = match verify_key {
		None => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, None)?,
		Some(k) => decrypt_raw_symmetric_internally(&key, encrypted_data, &head, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn decrypt_raw_symmetric_with_aad(
	key: &str,
	encrypted_data: &[u8],
	head: &str,
	aad: &[u8],
	verify_key_data: Option<&str>,
) -> Result<Vec<u8>, String>
{
	let key = key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let head = EncryptedHead::from_string(head).map_err(SdkError::JsonParseFailed)?;

	let decrypted = match verify_key {
		None => decrypt_raw_symmetric_with_aad_internally(&key, encrypted_data, &head, aad, None)?,
		Some(k) => decrypt_raw_symmetric_with_aad_internally(&key, encrypted_data, &head, aad, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_raw_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: Option<&str>) -> Result<(String, Vec<u8>), String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let (head, encrypted) = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_raw_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	let head = head
		.to_string()
		.map_err(|_e| SdkError::JsonToStringFailed)?;

	Ok((head, encrypted))
}

pub fn decrypt_raw_asymmetric(private_key: &str, encrypted_data: &[u8], head: &str, verify_key_data: Option<&str>) -> Result<Vec<u8>, String>
{
	let private_key = private_key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let head = EncryptedHead::from_string(head).map_err(SdkError::JsonParseFailed)?;

	let decrypted = match verify_key {
		None => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, None)?,
		Some(k) => decrypt_raw_asymmetric_internally(&private_key, encrypted_data, &head, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_symmetric(key: &str, data: &[u8], sign_key: Option<&str>) -> Result<Vec<u8>, String>
{
	let key = key.parse()?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_symmetric_internally(&key, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_symmetric(key: &str, encrypted_data: &[u8], verify_key_data: Option<&str>) -> Result<Vec<u8>, String>
{
	let key = key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_symmetric_internally(&key, encrypted_data, None)?,
		Some(k) => decrypt_symmetric_internally(&key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_asymmetric(reply_public_key_data: &str, data: &[u8], sign_key: Option<&str>) -> Result<Vec<u8>, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_asymmetric(private_key: &str, encrypted_data: &[u8], verify_key_data: Option<&str>) -> Result<Vec<u8>, String>
{
	let private_key = private_key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_asymmetric_internally(&private_key, encrypted_data, None)?,
		Some(k) => decrypt_asymmetric_internally(&private_key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_symmetric(key: &str, data: &str, sign_key: Option<&str>) -> Result<String, String>
{
	let key = key.parse()?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_symmetric_internally(&key, data, None)?,
		Some(k) => encrypt_string_symmetric_internally(&key, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_symmetric(key: &str, encrypted_data: &str, verify_key_data: Option<&str>) -> Result<String, String>
{
	let key = key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_string_symmetric_internally(&key, encrypted_data, None)?,
		Some(k) => decrypt_string_symmetric_internally(&key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn encrypt_string_asymmetric(reply_public_key_data: &str, data: &str, sign_key: Option<&str>) -> Result<String, String>
{
	let reply_public_key_data = UserPublicKeyData::from_string(reply_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let sign_key = prepare_sign_key(sign_key)?;

	let encrypted = match sign_key {
		//in match because we need a valid ref to the sign key format
		None => encrypt_string_asymmetric_internally(&reply_public_key_data, data, None)?,
		Some(k) => encrypt_string_asymmetric_internally(&reply_public_key_data, data, Some(&k))?,
	};

	Ok(encrypted)
}

pub fn decrypt_string_asymmetric(private_key: &str, encrypted_data: &str, verify_key_data: Option<&str>) -> Result<String, String>
{
	let private_key = private_key.parse()?;

	let verify_key = prepare_verify_key(verify_key_data)?;

	let decrypted = match verify_key {
		None => decrypt_string_asymmetric_internally(&private_key, encrypted_data, None)?,
		Some(k) => decrypt_string_asymmetric_internally(&private_key, encrypted_data, Some(&k))?,
	};

	Ok(decrypted)
}

pub fn prepare_register_sym_key(master_key: &str) -> Result<(String, String), String>
{
	let master_key = master_key.parse()?;

	let (server_input, key) = prepare_register_sym_key_internally(&master_key)?;

	Ok((server_input, key.to_string()?))
}

pub fn prepare_register_sym_key_by_public_key(reply_public_key: &str) -> Result<(String, String), String>
{
	let reply_public_key = UserPublicKeyData::from_string(reply_public_key).map_err(SdkError::JsonParseFailed)?;

	let (server_input, key) = prepare_register_sym_key_by_public_key_internally(&reply_public_key)?;

	Ok((server_input, key.to_string()?))
}

pub fn done_register_sym_key(key_id: &str, non_registered_sym_key: &str) -> Result<String, String>
{
	let mut non_registered_sym_key = non_registered_sym_key.parse()?;

	done_register_sym_key_internally(key_id, &mut non_registered_sym_key);

	Ok(non_registered_sym_key.to_string()?)
}

pub fn done_fetch_sym_key(master_key: &str, server_out: &str, non_registered: bool) -> Result<String, String>
{
	let master_key = master_key.parse()?;

	let out = done_fetch_sym_key_internally(&master_key, server_out, non_registered)?;

	Ok(out.to_string()?)
}

pub fn done_fetch_sym_key_by_private_key(private_key: &str, server_out: &str, non_registered: bool) -> Result<String, String>
{
	let private_key = private_key.parse()?;

	let out = done_fetch_sym_key_by_private_key_internally(&private_key, server_out, non_registered)?;

	Ok(out.to_string()?)
}

pub fn done_fetch_sym_keys(master_key: &str, server_out: &str) -> Result<(Vec<String>, u128, SymKeyId), String>
{
	let master_key = master_key.parse()?;

	let (out, last_time, last_id) = done_fetch_sym_keys_internally(&master_key, server_out)?;

	let out = out
		.into_iter()
		.map(|k| k.to_string())
		.collect::<Result<Vec<String>, _>>()?;

	Ok((out, last_time, last_id))
}

pub fn decrypt_sym_key(master_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	let master_key = master_key.parse()?;
	let encrypted_symmetric_key_info =
		GeneratedSymKeyHeadServerOutput::from_string(encrypted_symmetric_key_info).map_err(SdkError::JsonParseFailed)?;

	let out = decrypt_sym_key_internally(&master_key, &encrypted_symmetric_key_info)?;

	Ok(out.to_string()?)
}

pub fn decrypt_sym_key_by_private_key(private_key: &str, encrypted_symmetric_key_info: &str) -> Result<String, String>
{
	let private_key = private_key.parse()?;

	let encrypted_symmetric_key_info =
		GeneratedSymKeyHeadServerOutput::from_string(encrypted_symmetric_key_info).map_err(SdkError::JsonParseFailed)?;

	let out = decrypt_sym_key_by_private_key_internally(&private_key, &encrypted_symmetric_key_info)?;

	Ok(out.to_string()?)
}

pub fn generate_non_register_sym_key(master_key: &str) -> Result<(String, String), String>
{
	let master_key = master_key.parse()?;

	let (key, encrypted_key) = generate_non_register_sym_key_internally(&master_key)?;

	let exported_key = key.to_string()?;

	let exported_encrypted_key = encrypted_key
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?;

	Ok((exported_key, exported_encrypted_key))
}

pub fn generate_non_register_sym_key_by_public_key(reply_public_key: &str) -> Result<(String, String), String>
{
	let reply_public_key = UserPublicKeyData::from_string(reply_public_key).map_err(SdkError::JsonParseFailed)?;

	let (key, encrypted_key) = generate_non_register_sym_key_by_public_key_internally(&reply_public_key)?;

	let exported_key = key.to_string()?;

	let exported_encrypted_key = encrypted_key
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?;

	Ok((exported_key, exported_encrypted_key))
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;
	use core::str::FromStr;

	use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerInput;
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::SymKey;
	use sentc_crypto_utils::keys::SymKeyFormatInt;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_raw_symmetric(
			group_key,
			&encrypted,
			&head,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_aad()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let payload = b"payload1234567891011121314151617";

		let (head, encrypted) = encrypt_raw_symmetric_with_aad(group_key, text.as_bytes(), payload, None).unwrap();

		let decrypted = decrypt_raw_symmetric_with_aad(group_key, &encrypted, &head, payload, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig_with_aad()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let payload = b"payload1234567891011121314151617";

		let (head, encrypted) = encrypt_raw_symmetric_with_aad(group_key, text.as_bytes(), payload, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_raw_symmetric_with_aad(
			group_key,
			&encrypted,
			&head,
			payload,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (head, encrypted) = encrypt_raw_asymmetric(user_keys.exported_public_key.as_str(), text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_asymmetric(user_keys.private_key.as_str(), &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (head, encrypted) = encrypt_raw_asymmetric(
			user_keys.exported_public_key.as_str(),
			text.as_bytes(),
			Some(user_keys.sign_key.as_str()),
		)
		.unwrap();

		let decrypted = decrypt_raw_asymmetric(
			user_keys.private_key.as_str(),
			&encrypted,
			&head,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sig()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, Some(user_keys.exported_verify_key.as_str())).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let encrypted = encrypt_asymmetric(user_keys.exported_public_key.as_str(), text.as_bytes(), None).unwrap();

		let decrypted = decrypt_asymmetric(user_keys.private_key.as_str(), &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let encrypted = encrypt_asymmetric(
			user_keys.exported_public_key.as_str(),
			text.as_bytes(),
			Some(user_keys.sign_key.as_str()),
		)
		.unwrap();

		let decrypted = decrypt_asymmetric(
			user_keys.private_key.as_str(),
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";

		let encrypted = encrypt_string_symmetric(group_key, text, None).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sig()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let encrypted = encrypt_string_symmetric(group_key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, Some(user_keys.exported_verify_key.as_str())).unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let text = "123*+^êéèüöß@€&$ 👍";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let encrypted = encrypt_string_asymmetric(user_keys.exported_public_key.as_str(), text, None).unwrap();

		let decrypted = decrypt_string_asymmetric(user_keys.private_key.as_str(), &encrypted, None).unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_sig()
	{
		let text = "123*+^êéèüöß@€&$ 👍";
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let encrypted = encrypt_string_asymmetric(
			user_keys.exported_public_key.as_str(),
			text,
			Some(user_keys.sign_key.as_str()),
		)
		.unwrap();

		let decrypted = decrypt_string_asymmetric(
			user_keys.private_key.as_str(),
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_key()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let master_key = &key_data[0].group_key;

		let (server_in, _) = prepare_register_sym_key(master_key).unwrap();

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

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(
			&decrypted_key,
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_key_from_server()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let master_key = &key_data[0].group_key;

		let (server_in, _) = prepare_register_sym_key(master_key).unwrap();

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

		let decrypted_key = done_fetch_sym_key(master_key, server_response.to_string().unwrap().as_str(), false).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(
			&decrypted_key,
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_keys_as_array()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let master_key = &key_data[0].group_key;

		let (server_in, _) = prepare_register_sym_key(master_key).unwrap();
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();
		let server_out_0 = GeneratedSymKeyHeadServerOutput {
			alg: server_in.alg,
			encrypted_key_string: server_in.encrypted_key_string,
			master_key_id: server_in.master_key_id,
			key_id: "123".to_string(),
			time: 0,
		};

		let (server_in, _) = prepare_register_sym_key(master_key).unwrap();
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
			let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(user_keys.sign_key.as_str())).unwrap();

			let decrypted = decrypt_string_symmetric(
				&decrypted_key,
				&encrypted,
				Some(user_keys.exported_verify_key.as_str()),
			)
			.unwrap();

			assert_eq!(decrypted, text);
		}
	}

	#[test]
	fn test_generate_non_register_sym_key()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, _, _, _) = create_group(user_keys);
		let master_key = &key_data[0].group_key;

		let (key, encrypted_key) = generate_non_register_sym_key(master_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, Some(user_keys.exported_verify_key.as_str())).unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key(master_key, &encrypted_key).unwrap();

		let key = SymKeyFormatInt::from_str(&key).unwrap();
		let decrypted_key = SymKeyFormatInt::from_str(&decrypted_key).unwrap();

		match (key.key, decrypted_key.key) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(k1, k2);
			},
		}
	}

	#[test]
	fn test_generating_sym_key_by_public_key()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (server_in, non_registered_key) = prepare_register_sym_key_by_public_key(user_keys.exported_public_key.as_str()).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		let key = done_register_sym_key("123", &non_registered_key).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, Some(user_keys.exported_verify_key.as_str())).unwrap();

		assert_eq!(decrypted, text);

		//no test server output

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

		let decrypted_key = done_fetch_sym_key_by_private_key(
			user_keys.private_key.as_str(),
			server_response.to_string().unwrap().as_str(),
			false,
		)
		.unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(
			&decrypted_key,
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_generate_non_register_sym_key_by_public_key()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (key, encrypted_key) = generate_non_register_sym_key_by_public_key(&user_keys.exported_public_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, Some(user_keys.exported_verify_key.as_str())).unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key_by_private_key(&user_keys.private_key, &encrypted_key).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(user_keys.sign_key.as_str())).unwrap();

		let decrypted = decrypt_string_symmetric(
			&decrypted_key,
			&encrypted,
			Some(user_keys.exported_verify_key.as_str()),
		)
		.unwrap();

		assert_eq!(decrypted, text);

		let key = SymKeyFormatInt::from_str(&key).unwrap();
		let decrypted_key = SymKeyFormatInt::from_str(&decrypted_key).unwrap();

		match (key.key, decrypted_key.key) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(k1, k2);
			},
		}
	}
}
