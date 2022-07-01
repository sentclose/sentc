use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error, SignK, Sk};

use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally, reset_password_internally};
use crate::DoneLoginOutput;

pub fn register(password: String) -> Result<String, Error>
{
	register_internally(password)
}

pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	prepare_login_internally(password, salt_string, derived_encryption_key_alg)
}

pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: String) -> Result<DoneLoginOutput, Error>
{
	done_login_internally(&master_key_encryption, server_output)
}

pub fn change_password(
	old_pw: String,
	new_pw: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> Result<String, Error>
{
	change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

pub fn reset_password(new_password: String, decrypted_private_key: &Sk, decrypted_sign_key: &SignK) -> Result<String, Error>
{
	reset_password_internally(new_password, decrypted_private_key, decrypted_sign_key)
}

#[cfg(test)]
mod test
{
	use base64ct::{Base64, Encoding};
	use sendclose_crypto_common::user::{DoneLoginInput, RegisterData};
	use sendclose_crypto_core::{ClientRandomValue, Sk};

	use super::*;

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		println!("rust: {}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();
		let RegisterData {
			derived,
			master_key,
		} = out;

		//and now try to login
		//normally the salt gets calc by the api
		let client_random_value = Base64::decode_vec(derived.client_random_value.as_str()).unwrap();
		let client_random_value = match derived.derived_alg.as_str() {
			sendclose_crypto_core::ARGON_2_OUTPUT => ClientRandomValue::Argon2(client_random_value.try_into().unwrap()),
			_ => panic!("alg not found"),
		};

		let salt_from_rand_value = sendclose_crypto_core::generate_salt(client_random_value);
		let salt_from_rand_value = Base64::encode_string(&salt_from_rand_value);

		//back to the client, send prep login out string to the server if it is no err
		let (_, master_key_encryption_key) = prepare_login(password.to_string(), salt_from_rand_value, derived.derived_alg).unwrap();

		//get the server output back
		let server_output = DoneLoginInput {
			encrypted_master_key: master_key.encrypted_master_key,
			encrypted_private_key: derived.encrypted_private_key,
			encrypted_sign_key: derived.encrypted_sign_key,
			public_key_string: derived.public_key,
			verify_key_string: derived.verify_key,
			keypair_encrypt_alg: derived.keypair_encrypt_alg,
			keypair_sign_alg: derived.keypair_sign_alg,
		};

		let server_output = server_output.to_string().unwrap();

		//now save the values
		let login_out = done_login(&master_key_encryption_key, server_output).unwrap();

		let private_key = match login_out.private_key {
			Sk::Ecies(k) => k,
		};

		let mut arr = [0u8; 32];
		arr[0] = 123;
		arr[1] = 255;
		arr[2] = 254;
		arr[3] = 0;

		assert_ne!(private_key, arr);
	}
}
