use alloc::string::String;

use sendclose_crypto_common::user::DoneLoginInput;
use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error};

use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally, reset_password_internally};
use crate::util::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, VerifyKeyFormat};

pub fn register(password: String) -> Result<String, Error>
{
	register_internally(password)
}

pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	prepare_login_internally(password, salt_string, derived_encryption_key_alg)
}

pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &DoneLoginInput) -> Result<KeyData, Error>
{
	let out = done_login_internally(&master_key_encryption, server_output)?;

	Ok(KeyData {
		private_key: PrivateKeyFormat {
			key: out.private_key,
			key_id: out.keypair_encrypt_id.clone(),
		},
		sign_key: SignKeyFormat {
			key: out.sign_key,
			key_id: out.keypair_sign_id.clone(),
		},
		public_key: PublicKeyFormat {
			key: out.public_key,
			key_id: out.keypair_encrypt_id,
		},
		verify_key: VerifyKeyFormat {
			key: out.verify_key,
			key_id: out.keypair_sign_id,
		},
	})
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

pub fn reset_password(new_password: String, decrypted_private_key: &PrivateKeyFormat, decrypted_sign_key: &SignKeyFormat) -> Result<String, Error>
{
	reset_password_internally(new_password, &decrypted_private_key.key, &decrypted_sign_key.key)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;

	use sendclose_crypto_common::user::{ChangePasswordData, RegisterData};
	use sendclose_crypto_core::Sk;

	use super::*;
	use crate::test::{simulate_server_done_login, simulate_server_prepare_login};

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		std::println!("rust: {}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, master_key_encryption_key) = prepare_login(password.to_string(), salt_from_rand_value, out.derived.derived_alg.clone()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

		let private_key = match login_out.private_key.key {
			Sk::Ecies(k) => k,
		};

		let mut arr = [0u8; 32];
		arr[0] = 123;
		arr[1] = 255;
		arr[2] = 254;
		arr[3] = 0;

		assert_ne!(private_key, arr);
	}

	#[test]
	fn test_change_password()
	{
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(password.to_string()).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		let pw_change_out = change_password(
			password.to_string(),
			new_password.to_string(),
			salt_from_rand_value,
			out.master_key.encrypted_master_key.clone(),
			out.derived.derived_alg,
		)
		.unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_bytes()).unwrap();

		assert_ne!(pw_change_out.new_client_random_value, out.derived.client_random_value);

		assert_ne!(pw_change_out.new_encrypted_master_key, out.master_key.encrypted_master_key);
	}
}
