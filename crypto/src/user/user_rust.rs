use alloc::string::String;
use alloc::vec::Vec;

use sendclose_crypto_common::user::{DoneLoginServerKeysOutput, MultipleLoginServerOutput, PrepareLoginSaltServerOutput};
use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error};

use crate::user::{
	change_password_internally,
	done_login_internally,
	prepare_login_internally,
	prepare_update_user_keys_internally,
	register_internally,
	reset_password_internally,
};
use crate::util::{KeyData, PrivateKeyFormat, SignKeyFormat};

pub fn register(password: &str) -> Result<String, Error>
{
	register_internally(password)
}

pub fn prepare_login(password: &str, server_output: &PrepareLoginSaltServerOutput) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	prepare_login_internally(password, server_output)
}

pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &DoneLoginServerKeysOutput) -> Result<KeyData, Error>
{
	done_login_internally(&master_key_encryption, server_output)
}

pub fn change_password(
	old_pw: &str,
	new_pw: &str,
	old_salt: &str,
	encrypted_master_key: &str,
	derived_encryption_key_alg: &str,
) -> Result<String, Error>
{
	change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

//the feature marco here because of ide err, because the format would not match when rust feature is disabled.
#[cfg(feature = "rust")]
pub fn reset_password(new_password: &str, decrypted_private_key: &PrivateKeyFormat, decrypted_sign_key: &SignKeyFormat) -> Result<String, Error>
{
	#[cfg(feature = "rust")]
	reset_password_internally(new_password, decrypted_private_key, decrypted_sign_key)
}

pub fn prepare_update_user_keys(password: &str, server_output: &MultipleLoginServerOutput) -> Result<Vec<KeyData>, Error>
{
	prepare_update_user_keys_internally(password, server_output)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use sendclose_crypto_common::user::{ChangePasswordData, RegisterData};
	use sendclose_crypto_core::Sk;

	use super::*;
	use crate::test::{simulate_server_done_login, simulate_server_prepare_login};

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password).unwrap();

		std::println!("rust: {}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let password = "abc*èéöäüê";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

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

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		let pw_change_out = change_password(
			password,
			new_password,
			salt_from_rand_value.salt_string.as_str(),
			out.master_key.encrypted_master_key.as_str(),
			out.derived.derived_alg.as_str(),
		)
		.unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_bytes()).unwrap();

		assert_ne!(pw_change_out.new_client_random_value, out.derived.client_random_value);

		assert_ne!(pw_change_out.new_encrypted_master_key, out.master_key.encrypted_master_key);
	}
}
