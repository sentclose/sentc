use alloc::vec::Vec;

use sendclose_crypto_core::Error;

use crate::crypto::{decrypt_raw_symmetric_internally, encrypt_raw_symmetric_internally, EncryptedHead};
use crate::util::{SignKeyFormatInt, SymKeyFormatInt, VerifyKeyFormatInt};

pub fn encrypt_raw_symmetric(key: &SymKeyFormatInt, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	encrypt_raw_symmetric_internally(key, data, sign_key)
}

pub fn decrypt_raw_symmetric(
	key: &SymKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&VerifyKeyFormatInt>,
) -> Result<Vec<u8>, Error>
{
	decrypt_raw_symmetric_internally(key, encrypted_data, head, verify_key)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use sendclose_crypto_common::group::{CreateData, GroupKeyServerOutput, GroupServerData};
	use sendclose_crypto_common::user::RegisterData;

	use super::*;
	use crate::group::{get_group_data, prepare_create};
	use crate::test::{simulate_server_done_login, simulate_server_prepare_login};
	use crate::user::{done_login, prepare_login, register};

	#[test]
	fn test_encrypt_decrypt_raw()
	{
		//create a rust dummy user
		let password = "12345";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

		//create a group to use their sym key
		let group = prepare_create(&login_out.public_key).unwrap();
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		let group = get_group_data(&login_out.private_key, &group_server_output).unwrap();
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), None).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, None).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_raw_with_sig()
	{
		//create a rust dummy user
		let password = "12345";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

		//create a group to use their sym key
		let group = prepare_create(&login_out.public_key).unwrap();
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		let group = get_group_data(&login_out.private_key, &group_server_output).unwrap();
		let group_key = &group.keys[0].group_key;

		//now start encrypt and decrypt with the group master key
		let text = "123*+^êéèüöß";

		let (head, encrypted) = encrypt_raw_symmetric(group_key, text.as_bytes(), Some(&login_out.sign_key)).unwrap();

		let decrypted = decrypt_raw_symmetric(group_key, &encrypted, &head, Some(&login_out.verify_key)).unwrap();

		assert_eq!(text.as_bytes(), decrypted);
	}
}
