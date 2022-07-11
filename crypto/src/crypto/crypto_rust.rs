use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::Error;

use crate::crypto::{
	decrypt_asymmetric_internally,
	decrypt_raw_asymmetric_internally,
	decrypt_raw_symmetric_internally,
	decrypt_string_asymmetric_internally,
	decrypt_string_symmetric_internally,
	decrypt_symmetric_internally,
	encrypt_asymmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	encrypt_string_asymmetric_internally,
	encrypt_string_symmetric_internally,
	encrypt_symmetric_internally,
	EncryptedHead,
};
use crate::{PrivateKeyFormat, SignKeyFormat, SymKeyFormat};

pub fn encrypt_raw_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	encrypt_raw_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_raw_symmetric(
	key: &SymKeyFormat,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	decrypt_raw_symmetric_internally(key, encrypted_data, head, verify_key)
}

pub fn encrypt_raw_asymmetric(
	reply_public_key: &UserPublicKeyData,
	data: &[u8],
	sign_key: Option<&SignKeyFormat>,
) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	encrypt_raw_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_raw_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	decrypt_raw_asymmetric_internally(private_key, encrypted_data, head, verify_key)
}

pub fn encrypt_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<Vec<u8>, Error>
{
	encrypt_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_symmetric(key: &SymKeyFormat, encrypted_data_with_head: &[u8], verify_key: Option<&UserVerifyKeyData>) -> Result<Vec<u8>, Error>
{
	decrypt_symmetric_internally(key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_asymmetric(reply_public_key: &UserPublicKeyData, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<Vec<u8>, Error>
{
	encrypt_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	decrypt_asymmetric_internally(private_key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_string_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<String, Error>
{
	encrypt_string_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_string_symmetric(key: &SymKeyFormat, encrypted_data_with_head: &str, verify_key: Option<&UserVerifyKeyData>)
	-> Result<Vec<u8>, Error>
{
	decrypt_string_symmetric_internally(key, encrypted_data_with_head, verify_key)
}

pub fn encrypt_string_asymmetric(reply_public_key: &UserPublicKeyData, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<String, Error>
{
	encrypt_string_asymmetric_internally(reply_public_key, data, sign_key)
}

pub fn decrypt_string_asymmetric(
	private_key: &PrivateKeyFormat,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	decrypt_string_asymmetric_internally(private_key, encrypted_data_with_head, verify_key)
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let (user, _public_key, _verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

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
		let (user, _public_key, verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß@€&$";
		let (user, public_key, _verify_key) = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(&public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_asymmetric(&user.private_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß@€&$";
		let (user, public_key, verify_key) = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(&public_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_raw_asymmetric(&user.private_key, &encrypted, &head, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym()
	{
		let (user, _public_key, _verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_sym_with_sign()
	{
		let (user, _public_key, verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_symmetric(group_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_symmetric(group_key, &encrypted, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym()
	{
		let (user, public_key, _verify_key) = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_asymmetric(&public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_asymmetric(&user.private_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_asym_with_asign()
	{
		let (user, public_key, verify_key) = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_asymmetric(&public_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_asymmetric(&user.private_key, &encrypted, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym()
	{
		let (user, _public_key, _verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_sym_with_sign()
	{
		let (user, _public_key, verify_key) = create_user();

		let (group, _) = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_symmetric(group_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_string_symmetric(group_key, &encrypted, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym()
	{
		let (user, public_key, _verify_key) = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_asymmetric(&public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_string_asymmetric(&user.private_key, &encrypted, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}

	#[test]
	fn test_encrypt_decrypt_string_asym_with_asign()
	{
		let (user, public_key, verify_key) = create_user();

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß@€&$";

		let encrypted = encrypt_string_asymmetric(&public_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_string_asymmetric(&user.private_key, &encrypted, Some(&verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted)
	}
}
