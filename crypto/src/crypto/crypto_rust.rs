use alloc::vec::Vec;

use sendclose_crypto_core::Error;

use crate::crypto::{
	decrypt_raw_asymmetric_internally,
	decrypt_raw_symmetric_internally,
	encrypt_raw_asymmetric_internally,
	encrypt_raw_symmetric_internally,
	EncryptedHead,
};
use crate::{PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, VerifyKeyFormat};

pub fn encrypt_raw_symmetric(key: &SymKeyFormat, data: &[u8], sign_key: Option<&SignKeyFormat>) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	encrypt_raw_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_raw_symmetric(
	key: &SymKeyFormat,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&VerifyKeyFormat>,
) -> Result<Vec<u8>, Error>
{
	decrypt_raw_symmetric_internally(key, encrypted_data, head, verify_key)
}

pub fn encrypt_raw_asymmetric(
	reply_public_key: &PublicKeyFormat,
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
	verify_key: Option<&VerifyKeyFormat>,
) -> Result<Vec<u8>, Error>
{
	decrypt_raw_asymmetric_internally(private_key, encrypted_data, head, verify_key)
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::test::{create_group, create_user};

	#[test]
	fn test_encrypt_decrypt_sym_raw()
	{
		let user = create_user();

		let group = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sym_raw_with_sig()
	{
		//create a rust dummy user
		let user = create_user();

		let group = create_group(&user);
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, Some(&user.verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw()
	{
		let text = "123*+^êéèüöß";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(&user.public_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_asymmetric(&user.private_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_asym_raw_with_sig()
	{
		let text = "123*+^êéèüöß";
		let user = create_user();

		let (head, encrypted) = encrypt_raw_asymmetric(&user.public_key, text.as_bytes(), Some(&user.sign_key)).unwrap();

		let decrypted = decrypt_raw_asymmetric(&user.private_key, &encrypted, &head, Some(&user.verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}
}
