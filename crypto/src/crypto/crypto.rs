use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerInput, GeneratedSymKeyHeadServerOutput};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::SymKeyId;
use sentc_crypto_core::cryptomat::{CryptoAlg, SymKeyComposer, SymKeyGen};
use sentc_crypto_core::SymmetricKey as CoreSymmetricKey;
use sentc_crypto_utils::keys::{PublicKey, SecretKey, SymmetricKey};
use serde::{Deserialize, Serialize};

use crate::util::public::handle_server_response;
use crate::SdkError;

/**
Get the head and the data.

This can not only be used internally, to get the used key_id
 */
pub fn split_head_and_encrypted_data<'a, T: Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), SdkError>
{
	Ok(sentc_crypto_utils::keys::split_head_and_encrypted_data(
		data_with_head,
	)?)
}

/**
Get head from string.

Just the head because of lifetime issues and we need the full data for encrypt and decrypt
 */
pub fn split_head_and_encrypted_string(encrypted_data_with_head: &str) -> Result<EncryptedHead, SdkError>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let (head, _) = split_head_and_encrypted_data(&encrypted)?;

	Ok(head)
}

pub fn put_head_and_encrypted_data<T: Serialize>(head: &T, encrypted: &[u8]) -> Result<Vec<u8>, SdkError>
{
	let head = serde_json::to_string(head).map_err(|_| SdkError::JsonToStringFailed)?;

	let mut out = Vec::with_capacity(head.len() + 1 + encrypted.len());

	out.extend(head.as_bytes());
	out.extend([0u8]);
	out.extend(encrypted);

	Ok(out)
}

/**
Get the head from string

This can be used to get the head struct when getting the head as string, like raw decrypt in the non rust sdk.
 */
pub fn deserialize_head_from_string(head: &str) -> Result<EncryptedHead, SdkError>
{
	Ok(EncryptedHead::from_string(head)?)
}

//__________________________________________________________________________________________________

/**
# Prepare key registration on the server

1. create a new symmetric key
2. export the symmetric key in base64
3. encrypt the symmetric key with the master key
4. return the server input
 */
pub fn prepare_register_sym_key(master_key: &SymmetricKey) -> Result<(String, SymmetricKey), SdkError>
{
	let (out, key) = prepare_registered_sym_key_internally_private(master_key)?;

	Ok((out.to_string().map_err(|_| SdkError::JsonToStringFailed)?, key))
}

fn prepare_registered_sym_key_internally_private(master_key: &SymmetricKey) -> Result<(GeneratedSymKeyHeadServerInput, SymmetricKey), SdkError>
{
	let (encrypted_key, key) = CoreSymmetricKey::generate_symmetric_with_sym_key(&master_key.key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let sym_key_format = SymmetricKey {
		key,
		key_id: "".to_string(),
	};

	Ok((
		GeneratedSymKeyHeadServerInput {
			encrypted_key_string,
			alg: sym_key_format.key.get_alg_str().to_string(),
			master_key_id: master_key.key_id.to_string(),
		},
		sym_key_format,
	))
}

/**
In two fn to avoid an extra request to get the key with the id
 */
pub fn done_register_sym_key(key_id: &str, non_registered_sym_key: &mut SymmetricKey)
{
	//put the key id to the non-registered key
	non_registered_sym_key.key_id = key_id.to_string();
}

/**
# Prepare key register

but this time encrypted by a users public key

Return the non-registered version but only to register the key on the server to get the id,
then put the id back in
 */
pub fn prepare_register_sym_key_by_public_key(reply_public_key: &UserPublicKeyData) -> Result<(String, SymmetricKey), SdkError>
{
	let (out, key) = prepare_register_sym_key_by_public_key_internally_private(reply_public_key)?;

	Ok((out.to_string().map_err(|_| SdkError::JsonToStringFailed)?, key))
}

fn prepare_register_sym_key_by_public_key_internally_private(
	reply_public_key: &UserPublicKeyData,
) -> Result<(GeneratedSymKeyHeadServerInput, SymmetricKey), SdkError>
{
	let public_key = PublicKey::try_from(reply_public_key)?;

	let (encrypted_key, key) = CoreSymmetricKey::generate_symmetric_with_public_key(&public_key.key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let sym_key_format = SymmetricKey {
		key,
		key_id: "".to_string(),
	};

	Ok((
		GeneratedSymKeyHeadServerInput {
			encrypted_key_string,
			alg: sym_key_format.key.get_alg_str().to_string(),
			master_key_id: public_key.key_id,
		},
		sym_key_format,
	))
}

/**
# Get the key from server fetch

Decrypted the server output with the master key
 */
pub fn done_fetch_sym_key(master_key: &SymmetricKey, server_out: &str, non_registered: bool) -> Result<SymmetricKey, SdkError>
{
	let out: GeneratedSymKeyHeadServerOutput = if non_registered {
		GeneratedSymKeyHeadServerOutput::from_string(server_out)?
	} else {
		handle_server_response(server_out)?
	};

	decrypt_sym_key(master_key, &out)
}

/**
# Get the key from server fetch

decrypt it with the private key
 */
pub fn done_fetch_sym_key_by_private_key(private_key: &SecretKey, server_out: &str, non_registered: bool) -> Result<SymmetricKey, SdkError>
{
	let out: GeneratedSymKeyHeadServerOutput = if non_registered {
		GeneratedSymKeyHeadServerOutput::from_string(server_out)?
	} else {
		handle_server_response(server_out)?
	};

	decrypt_sym_key_by_private_key(private_key, &out)
}

/**
# Get the key from server fetch

like done_fetch_sym_key_internally but this time with an array of keys as server output
 */
pub fn done_fetch_sym_keys(master_key: &SymmetricKey, server_out: &str) -> Result<(Vec<SymmetricKey>, u128, SymKeyId), SdkError>
{
	let server_out: Vec<GeneratedSymKeyHeadServerOutput> = handle_server_response(server_out)?;

	let mut keys = Vec::with_capacity(server_out.len());

	let last_element = &server_out[server_out.len() - 1];
	let last_time = last_element.time;
	let last_id = last_element.key_id.to_string();

	for out in server_out {
		keys.push(decrypt_sym_key(master_key, &out)?)
	}

	Ok((keys, last_time, last_id))
}

/**
# Get a symmetric key which was encrypted by a master key

Backwards the process in prepare_register_sym_key.

1. get the bytes of the encrypted symmetric key
2. get the sym internal format by decrypting it with the master key
4. return the key incl. key id in the right format
 */
pub fn decrypt_sym_key(master_key: &SymmetricKey, encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput) -> Result<SymmetricKey, SdkError>
{
	let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

	let key = CoreSymmetricKey::decrypt_key_by_sym_key(
		&master_key.key,
		&encrypted_sym_key,
		encrypted_symmetric_key_info.alg.as_str(),
	)?;

	Ok(SymmetricKey {
		key,
		key_id: encrypted_symmetric_key_info.key_id.to_string(),
	})
}

/**
# Get a symmetric key which was encrypted by a public key
 */
pub fn decrypt_sym_key_by_private_key(
	private_key: &SecretKey,
	encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput,
) -> Result<SymmetricKey, SdkError>
{
	let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

	let key = CoreSymmetricKey::decrypt_key_by_master_key(
		&private_key.key,
		&encrypted_sym_key,
		encrypted_symmetric_key_info.alg.as_str(),
	)?;

	Ok(SymmetricKey {
		key,
		key_id: encrypted_symmetric_key_info.key_id.to_string(),
	})
}

/**
# Simulates the server key output

This is used when the keys are not managed by the sentclose server.

First call prepare_register_sym_key_internally to encrypt the key, then decrypt_sym_key_internally to get the raw key.

Return both, the decrypted to use it, the encrypted to save it and use it for the next time with decrypt_sym_key_internally
 */
pub fn generate_non_register_sym_key(master_key: &SymmetricKey) -> Result<(SymmetricKey, GeneratedSymKeyHeadServerOutput), SdkError>
{
	let (pre_out, key) = prepare_registered_sym_key_internally_private(master_key)?;

	let server_output = GeneratedSymKeyHeadServerOutput {
		alg: pre_out.alg,
		encrypted_key_string: pre_out.encrypted_key_string,
		master_key_id: pre_out.master_key_id,
		key_id: "non_registered".to_string(),
		time: 0,
	};

	Ok((key, server_output))
}

pub fn generate_non_register_sym_key_by_public_key(
	reply_public_key: &UserPublicKeyData,
) -> Result<(SymmetricKey, GeneratedSymKeyHeadServerOutput), SdkError>
{
	let (pre_out, key) = prepare_register_sym_key_by_public_key_internally_private(reply_public_key)?;

	let server_output = GeneratedSymKeyHeadServerOutput {
		alg: pre_out.alg,
		encrypted_key_string: pre_out.encrypted_key_string,
		master_key_id: pre_out.master_key_id,
		key_id: "non_registered".to_string(),
		time: 0,
	};

	Ok((key, server_output))
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerInput;
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_utils::cryptomat::{PkFromUserKeyWrapper, SkCryptoWrapper, SymKeyCrypto};
	use sentc_crypto_utils::keys::SignKey;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = group_key
			.encrypt_raw(text.as_bytes(), None::<&SignKey>)
			.unwrap();

		let decrypted = group_key.decrypt_raw(&encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		//create a rust dummy user
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = group_key
			.encrypt_raw(text.as_bytes(), Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = group_key
			.decrypt_raw(&encrypted, &head, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_aad()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";
		let payload = b"payload1234567891011121314151617";

		let (head, encrypted) = group_key
			.encrypt_raw_with_aad(text.as_bytes(), payload, None::<&SignKey>)
			.unwrap();

		let decrypted = group_key
			.decrypt_raw_with_aad(&encrypted, payload, &head, None)
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig_with_aad()
	{
		//create a rust dummy user
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";
		let payload = b"payload1234567891011121314151617";

		let (head, encrypted) = group_key
			.encrypt_raw_with_aad(text.as_bytes(), payload, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = group_key
			.decrypt_raw_with_aad(
				&encrypted,
				payload,
				&head,
				Some(&user.user_keys[0].exported_verify_key),
			)
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = PublicKey::encrypt_raw_with_user_key(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			None::<&SignKey>,
		)
		.unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt_raw(&encrypted, &head, None)
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = PublicKey::encrypt_raw_with_user_key(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			Some(&user.user_keys[0].sign_key),
		)
		.unwrap();

		let decrypted = &user.user_keys[0]
			.private_key
			.decrypt_raw(&encrypted, &head, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = group_key
			.encrypt(text.as_bytes(), None::<&SignKey>)
			.unwrap();

		let decrypted = group_key.decrypt(&encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_aad()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let payload = b"payload1234567891011121314151617";

		let encrypted = group_key
			.encrypt_with_aad(text.as_bytes(), payload, None::<&SignKey>)
			.unwrap();

		let decrypted = group_key
			.decrypt_with_aad(&encrypted, payload, None)
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_wrong_aad()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let payload = b"payload1234567891011121314151617";
		let payload2 = b"payload1234567891011121314151618";

		let encrypted = group_key
			.encrypt_with_aad(text.as_bytes(), payload, None::<&SignKey>)
			.unwrap();

		let decrypted = group_key.decrypt_with_aad(&encrypted, payload2, None);

		match decrypted {
			Err(_e) => {},
			_ => panic!("should be error"),
		}
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sign()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = group_key
			.encrypt(text.as_bytes(), Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = group_key
			.decrypt(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = PublicKey::encrypt_with_user_key(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			None::<&SignKey>,
		)
		.unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt(&encrypted, None)
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_sign()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = PublicKey::encrypt_with_user_key(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			Some(&user.user_keys[0].sign_key),
		)
		.unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = group_key.encrypt_string(text, None::<&SignKey>).unwrap();

		let decrypted = group_key.decrypt_string(&encrypted, None).unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_wit_aad()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		let text = "123*+^êéèüöß@€&$ 👍 🚀";
		let payload = "payload1234567891011121314151617";

		let encrypted = group_key
			.encrypt_string_with_aad(text, payload, None::<&SignKey>)
			.unwrap();

		let decrypted = group_key
			.decrypt_string_with_aad(&encrypted, payload, None)
			.unwrap();

		assert_eq!(text, decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sign()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = group_key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = group_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = PublicKey::encrypt_string_with_user_key(&user.user_keys[0].exported_public_key, text, None::<&SignKey>).unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt_string(&encrypted, None)
			.unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_sign()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = PublicKey::encrypt_string_with_user_key(
			&user.user_keys[0].exported_public_key,
			text,
			Some(&user.user_keys[0].sign_key),
		)
		.unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_sym_key()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
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
		let decrypted_key = decrypt_sym_key(master_key, &server_out).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = decrypted_key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = decrypted_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_key_from_server()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let master_key = &key_data[0].group_key;

		let (server_in, _) = prepare_register_sym_key(master_key).unwrap();

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

		let encrypted = decrypted_key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = decrypted_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_keys_as_array()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
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

		//test server out decrypt
		let server_response = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_outputs),
		};

		let (decrypted_keys, _, _) = done_fetch_sym_keys(master_key, server_response.to_string().unwrap().as_str()).unwrap();

		let text = "123*+^êéèüöß@€&$";

		for decrypted_key in decrypted_keys {
			let encrypted = decrypted_key
				.encrypt_string(text, Some(&user.user_keys[0].sign_key))
				.unwrap();

			let decrypted = decrypted_key
				.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
				.unwrap();

			assert_eq!(decrypted, text);
		}
	}

	#[test]
	fn test_generate_non_register_sym_key()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let master_key = &key_data[0].group_key;

		let (key, encrypted_key) = generate_non_register_sym_key(master_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key(master_key, &encrypted_key).unwrap();

		assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
	}

	#[test]
	fn test_generating_sym_key_by_public_key()
	{
		let user = create_user();

		let (server_in, mut key) = prepare_register_sym_key_by_public_key(&user.user_keys[0].exported_public_key).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		done_register_sym_key("123", &mut key);

		let text = "123*+^êéèüöß@€&$";

		let encrypted = key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

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
			&user.user_keys[0].private_key,
			server_response.to_string().unwrap().as_str(),
			false,
		)
		.unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = decrypted_key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = decrypted_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_generate_non_register_sym_key_by_public_key()
	{
		let user = create_user();

		let (key, encrypted_key) = generate_non_register_sym_key_by_public_key(&user.user_keys[0].exported_public_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key_by_private_key(&user.user_keys[0].private_key, &encrypted_key).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = decrypted_key
			.encrypt_string(text, Some(&user.user_keys[0].sign_key))
			.unwrap();

		let decrypted = decrypted_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
	}
}
