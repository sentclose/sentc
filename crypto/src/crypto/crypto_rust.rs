use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerOutput;
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
	done_fetch_sym_key_by_private_key_internally,
	done_fetch_sym_key_internally,
	done_fetch_sym_keys_internally,
	done_register_sym_key_internally,
	encrypt_asymmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	encrypt_string_asymmetric_internally,
	encrypt_string_symmetric_internally,
	encrypt_symmetric_internally,
	generate_non_register_sym_key_internally,
	prepare_register_sym_key_by_public_key_internally,
	prepare_register_sym_key_internally,
	split_head_and_encrypted_data_internally,
	split_head_and_encrypted_string_internally,
	EncryptedHead,
};
use crate::{PrivateKeyFormat, SdkError, SignKeyFormat, SymKeyFormat};

pub fn split_head_and_encrypted_data(data_with_head: &[u8]) -> Result<(EncryptedHead, &[u8]), SdkError>
{
	split_head_and_encrypted_data_internally(data_with_head)
}

pub fn split_head_and_encrypted_string(data_with_head: &str) -> Result<EncryptedHead, SdkError>
{
	split_head_and_encrypted_string_internally(data_with_head)
}

pub fn deserialize_head_from_string(head: &str) -> Result<EncryptedHead, SdkError>
{
	deserialize_head_from_string_internally(head)
}

pub fn encrypt_raw_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<(EncryptedHead, Vec<u8>), SdkError>
{
	encrypt_raw_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_raw_symmetric(
	key: &SymKeyFormat,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	decrypt_raw_symmetric_internally(key, encrypted_data, head, verify_key)
}

pub fn encrypt_raw_asymmetric(
	reply_public_key: &UserPublicKeyData,
	data: &[u8],
	sign_key: Option<&SignKeyFormat>,
) -> Result<(EncryptedHead, Vec<u8>), SdkError>
{
	encrypt_raw_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_raw_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	decrypt_raw_asymmetric_internally(private_key, encrypted_data, head, verify_key)
}

pub fn encrypt_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<Vec<u8>, SdkError>
{
	encrypt_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_symmetric(key: &SymKeyFormat, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, SdkError>
{
	decrypt_symmetric_internally(key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_asymmetric(reply_public_key: &UserPublicKeyData, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<Vec<u8>, SdkError>
{
	encrypt_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	decrypt_asymmetric_internally(private_key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_string_symmetric(key: &SymKeyFormat, data: &str, sign_key: Option<&SignKeyFormat>) -> Result<String, SdkError>
{
	encrypt_string_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_string_symmetric(
	key: &SymKeyFormat,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	decrypt_string_symmetric_internally(key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_string_asymmetric(reply_public_key: &UserPublicKeyData, data: &str, sign_key: Option<&SignKeyFormat>) -> Result<String, SdkError>
{
	encrypt_string_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_string_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	decrypt_string_asymmetric_internally(private_key, encrypted_data_with_head, verify_key)
}

pub fn prepare_register_sym_key(master_key: &SymKeyFormat) -> Result<(String, SymKeyFormat), SdkError>
{
	prepare_register_sym_key_internally(master_key)
}

pub fn prepare_register_sym_key_by_public_key(reply_public_key: &UserPublicKeyData) -> Result<(String, SymKeyFormat), SdkError>
{
	prepare_register_sym_key_by_public_key_internally(&reply_public_key)
}

pub fn done_register_sym_key(key_id: &str, non_registered_sym_key: &mut SymKeyFormat)
{
	done_register_sym_key_internally(key_id, non_registered_sym_key)
}

pub fn done_fetch_sym_key(master_key: &SymKeyFormat, server_out: &str) -> Result<SymKeyFormat, SdkError>
{
	done_fetch_sym_key_internally(master_key, server_out)
}

pub fn done_fetch_sym_keys(master_key: &SymKeyFormat, server_out: &str) -> Result<(Vec<SymKeyFormat>, u128, SymKeyId), SdkError>
{
	done_fetch_sym_keys_internally(master_key, server_out)
}

pub fn done_fetch_sym_key_by_private_key(private_key: &PrivateKeyFormat, server_out: &str) -> Result<SymKeyFormat, SdkError>
{
	done_fetch_sym_key_by_private_key_internally(private_key, server_out)
}

pub fn decrypt_sym_key(master_key: &SymKeyFormat, encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput) -> Result<SymKeyFormat, SdkError>
{
	decrypt_sym_key_internally(master_key, encrypted_symmetric_key_info)
}

pub fn generate_non_register_sym_key(master_key: &SymKeyFormat) -> Result<(SymKeyFormat, GeneratedSymKeyHeadServerOutput), SdkError>
{
	generate_non_register_sym_key_internally(master_key)
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

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		//create a rust dummy user
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(&user.keys.exported_public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_asymmetric(&user.keys.private_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(
			&user.keys.exported_public_key,
			text.as_bytes(),
			Some(&user.keys.sign_key),
		)
		.unwrap();

		let decrypted = decrypt_raw_asymmetric(
			&user.keys.private_key,
			&encrypted,
			&head,
			Some(&user.keys.exported_verify_key),
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

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sign()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_asymmetric(&user.keys.exported_public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_asymmetric(&user.keys.private_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_asign()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_asymmetric(
			&user.keys.exported_public_key,
			text.as_bytes(),
			Some(&user.keys.sign_key),
		)
		.unwrap();

		let decrypted = decrypt_asymmetric(
			&user.keys.private_key,
			&encrypted,
			Some(&user.keys.exported_verify_key),
		)
		.unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text, None).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sign()
	{
		let user = create_user();

		let (_, key_data, _) = create_group(&user.keys);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_asymmetric(&user.keys.exported_public_key, text, None).unwrap();

		let decrypted = decrypt_string_asymmetric(&user.keys.private_key, &encrypted, None).unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_asign()
	{
		let user = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_asymmetric(&user.keys.exported_public_key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_asymmetric(
			&user.keys.private_key,
			&encrypted,
			Some(&user.keys.exported_verify_key),
		)
		.unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_sym_key()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
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

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_key_from_server()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
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

		let decrypted_key = done_fetch_sym_key(master_key, server_response.to_string().unwrap().as_str()).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(decrypted, text);
	}

	#[test]
	fn test_getting_sym_keys_as_array()
	{
		let user = create_user();
		let (_, key_data, _) = create_group(&user.keys);
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
			let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(&user.keys.sign_key)).unwrap();

			let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

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

		let encrypted = encrypt_string_symmetric(&key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = decrypt_sym_key(master_key, &encrypted_key).unwrap();

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

		let (server_in, mut key) = prepare_register_sym_key_by_public_key(&user.keys.exported_public_key).unwrap();

		//get the server output
		let server_in = GeneratedSymKeyHeadServerInput::from_string(server_in.as_str()).unwrap();

		done_register_sym_key("123", &mut key);

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(&key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

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

		let decrypted_key = done_fetch_sym_key_by_private_key(&user.keys.private_key, server_response.to_string().unwrap().as_str()).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(&decrypted_key, text, Some(&user.keys.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(&decrypted_key, &encrypted, Some(&user.keys.exported_verify_key)).unwrap();

		assert_eq!(decrypted, text);
	}
}
