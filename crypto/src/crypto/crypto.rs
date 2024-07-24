use alloc::string::ToString;
use alloc::vec::Vec;
use core::marker::PhantomData;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerOutput};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_core::cryptomat::{CryptoAlg, SymKeyComposer, SymKeyGen};
use sentc_crypto_utils::cryptomat::{PkFromUserKeyWrapper, SkWrapper, SymKeyComposerWrapper, SymKeyGenWrapper, SymKeyWrapper};
use serde::{Deserialize, Serialize};

use crate::util::public::handle_server_response;
use crate::SdkError;

/**
Get the head and the data.

This can not only be used internally, to get the used key_id
 */
pub fn split_head_and_encrypted_data<'a, T: Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), SdkError>
{
	Ok(sentc_crypto_utils::split_head_and_encrypted_data(data_with_head)?)
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

pub struct KeyGenerator<SGen, SC, P>
{
	_sgen: PhantomData<SGen>,
	_sc: PhantomData<SC>,
	_p: PhantomData<P>,
}

impl<SGen: SymKeyGenWrapper, SC: SymKeyComposerWrapper, P: PkFromUserKeyWrapper> KeyGenerator<SGen, SC, P>
{
	/**
	# Get the key from server fetch

	Decrypted the server output with the master key
	 */
	pub fn done_fetch_sym_key(master_key: &impl SymKeyWrapper, server_out: &str, non_registered: bool) -> Result<SC::SymmetricKeyWrapper, SdkError>
	{
		let out: GeneratedSymKeyHeadServerOutput = if non_registered {
			GeneratedSymKeyHeadServerOutput::from_string(server_out)?
		} else {
			handle_server_response(server_out)?
		};

		Self::decrypt_sym_key(master_key, &out)
	}

	/**
	# Get the key from server fetch

	decrypt it with the private key
	 */
	pub fn done_fetch_sym_key_by_private_key(
		private_key: &impl SkWrapper,
		server_out: &str,
		non_registered: bool,
	) -> Result<SC::SymmetricKeyWrapper, SdkError>
	{
		let out: GeneratedSymKeyHeadServerOutput = if non_registered {
			GeneratedSymKeyHeadServerOutput::from_string(server_out)?
		} else {
			handle_server_response(server_out)?
		};

		Self::decrypt_sym_key_by_private_key(private_key, &out)
	}

	/**
	# Get a symmetric key which was encrypted by a master key

	Backwards the process in prepare_register_sym_key.

	1. get the bytes of the encrypted symmetric key
	2. get the sym internal format by decrypting it with the master key
	4. return the key incl. key id in the right format
	 */
	pub fn decrypt_sym_key(
		master_key: &impl SymKeyWrapper,
		encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput,
	) -> Result<SC::SymmetricKeyWrapper, SdkError>
	{
		let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

		let key = SC::Composer::decrypt_key_by_sym_key(
			master_key.get_key(),
			&encrypted_sym_key,
			encrypted_symmetric_key_info.alg.as_str(),
		)?;

		Ok(SC::from_inner(key, encrypted_symmetric_key_info.key_id.to_string()))
	}

	/**
	# Get a symmetric key which was encrypted by a public key
	 */
	pub fn decrypt_sym_key_by_private_key(
		private_key: &impl SkWrapper,
		encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput,
	) -> Result<SC::SymmetricKeyWrapper, SdkError>
	{
		let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

		let key = SC::Composer::decrypt_key_by_master_key(
			private_key.get_key(),
			&encrypted_sym_key,
			encrypted_symmetric_key_info.alg.as_str(),
		)?;

		Ok(SC::from_inner(key, encrypted_symmetric_key_info.key_id.to_string()))
	}

	/**
	# Simulates the server key output

	This is used when the keys are not managed by the sentclose server.

	First call prepare_register_sym_key_internally to encrypt the key, then decrypt_sym_key_internally to get the raw key.

	Return both, the decrypted to use it, the encrypted to save it and use it for the next time with decrypt_sym_key_internally
	 */
	pub fn generate_non_register_sym_key(
		master_key: &impl SymKeyWrapper,
	) -> Result<(SGen::SymmetricKeyWrapper, GeneratedSymKeyHeadServerOutput), SdkError>
	{
		let (encrypted_key, key) = SGen::KeyGen::generate_symmetric_with_sym_key(master_key.get_key())?;

		let encrypted_key_string = Base64::encode_string(&encrypted_key);

		let sym_key_format = SGen::from_inner(key, "".to_string());

		let server_output = GeneratedSymKeyHeadServerOutput {
			alg: sym_key_format.get_key().get_alg_str().to_string(),
			encrypted_key_string,
			master_key_id: master_key.get_id().to_string(),
			key_id: "non_registered".to_string(),
			time: 0,
		};

		Ok((sym_key_format, server_output))
	}

	pub fn generate_non_register_sym_key_by_public_key(
		reply_public_key: &UserPublicKeyData,
	) -> Result<(SGen::SymmetricKeyWrapper, GeneratedSymKeyHeadServerOutput), SdkError>
	{
		let public_key = P::from_user_key(reply_public_key)?;

		let (encrypted_key, key) = SGen::KeyGen::generate_symmetric_with_public_key(&public_key)?;

		let encrypted_key_string = Base64::encode_string(&encrypted_key);

		let sym_key_format = SGen::from_inner(key, "".to_string());

		let server_output = GeneratedSymKeyHeadServerOutput {
			alg: sym_key_format.get_key().get_alg_str().to_string(),
			encrypted_key_string,
			master_key_id: reply_public_key.public_key_id.to_string(),
			key_id: "non_registered".to_string(),
			time: 0,
		};

		Ok((sym_key_format, server_output))
	}
}

#[cfg(test)]
mod test
{
	use sentc_crypto_utils::cryptomat::{PkFromUserKeyWrapper, SkCryptoWrapper, SymKeyCrypto};

	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[cfg(feature = "std_keys")]
	pub type TestKeyGenerator = crate::keys::std::StdKeyGenerator;
	#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
	pub type TestKeyGenerator = crate::keys::fips::FipsKeyGenerator;
	#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
	pub type TestKeyGenerator = crate::keys::rec::RecKeyGenerator;

	#[cfg(feature = "std_keys")]
	pub type TestPublicKey = sentc_crypto_std_keys::util::PublicKey;
	#[cfg(all(feature = "fips_keys", not(feature = "std_keys")))]
	pub type TestPublicKey = sentc_crypto_fips_keys::util::PublicKey;
	#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
	pub type TestPublicKey = sentc_crypto_rec_keys::util::PublicKey;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();

		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let group_key = &key_data[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = group_key.encrypt_raw(text.as_bytes()).unwrap();

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
			.encrypt_raw_with_sign(text.as_bytes(), &user.user_keys[0].sign_key)
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
			.encrypt_raw_with_aad(text.as_bytes(), payload)
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
			.encrypt_raw_with_aad_with_sign(text.as_bytes(), payload, &user.user_keys[0].sign_key)
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

		let (head, encrypted) = TestPublicKey::encrypt_raw_with_user_key(&user.user_keys[0].exported_public_key, text.as_bytes()).unwrap();

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

		let (head, encrypted) = TestPublicKey::encrypt_raw_with_user_key_with_sign(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			&user.user_keys[0].sign_key,
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

		let encrypted = group_key.encrypt(text.as_bytes()).unwrap();

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
			.encrypt_with_aad(text.as_bytes(), payload)
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
			.encrypt_with_aad(text.as_bytes(), payload)
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
			.encrypt_with_sign(text.as_bytes(), &user.user_keys[0].sign_key)
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

		let encrypted = TestPublicKey::encrypt_with_user_key(&user.user_keys[0].exported_public_key, text.as_bytes()).unwrap();

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

		let encrypted = TestPublicKey::encrypt_with_user_key_with_sign(
			&user.user_keys[0].exported_public_key,
			text.as_bytes(),
			&user.user_keys[0].sign_key,
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

		let encrypted = group_key.encrypt_string(text).unwrap();

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

		let encrypted = group_key.encrypt_string_with_aad(text, payload).unwrap();

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
			.encrypt_string_with_sign(text, &user.user_keys[0].sign_key)
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

		let encrypted = TestPublicKey::encrypt_string_with_user_key(&user.user_keys[0].exported_public_key, text).unwrap();

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

		let encrypted = TestPublicKey::encrypt_string_with_user_key_with_sign(
			&user.user_keys[0].exported_public_key,
			text,
			&user.user_keys[0].sign_key,
		)
		.unwrap();

		let decrypted = user.user_keys[0]
			.private_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(text, decrypted)
	}

	#[test]
	fn test_generate_non_register_sym_key()
	{
		let user = create_user();
		let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
		let master_key = &key_data[0].group_key;

		let (key, encrypted_key) = TestKeyGenerator::generate_non_register_sym_key(master_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = key
			.encrypt_string_with_sign(text, &user.user_keys[0].sign_key)
			.unwrap();

		let decrypted = key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = TestKeyGenerator::decrypt_sym_key(master_key, &encrypted_key).unwrap();

		assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
	}

	#[test]
	fn test_generate_non_register_sym_key_by_public_key()
	{
		let user = create_user();

		let (key, encrypted_key) = TestKeyGenerator::generate_non_register_sym_key_by_public_key(&user.user_keys[0].exported_public_key).unwrap();

		//test the encrypt / decrypt
		let text = "123*+^êéèüöß@€&$";

		let encrypted = key
			.encrypt_string_with_sign(text, &user.user_keys[0].sign_key)
			.unwrap();

		let decrypted = key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		//check if we can decrypt the key with the master key

		let decrypted_key = TestKeyGenerator::decrypt_sym_key_by_private_key(&user.user_keys[0].private_key, &encrypted_key).unwrap();

		let text = "123*+^êéèüöß@€&$";

		let encrypted = decrypted_key
			.encrypt_string_with_sign(text, &user.user_keys[0].sign_key)
			.unwrap();

		let decrypted = decrypted_key
			.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
			.unwrap();

		assert_eq!(decrypted, text);

		assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
	}
}
