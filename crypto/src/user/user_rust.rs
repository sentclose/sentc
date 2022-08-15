use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::MultipleLoginServerOutput;
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;

use crate::user::{
	change_password_internally,
	done_check_user_identifier_available_internally,
	done_login_internally,
	done_register_internally,
	prepare_check_user_identifier_available_internally,
	prepare_login_internally,
	prepare_login_start_internally,
	prepare_refresh_jwt_internally,
	prepare_update_user_keys_internally,
	prepare_user_identifier_update_internally,
	register_internally,
	reset_password_internally,
};
use crate::util::{KeyData, PrivateKeyFormat, SignKeyFormat, UserData};
use crate::SdkError;

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, SdkError>
{
	prepare_check_user_identifier_available_internally(user_identifier)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, SdkError>
{
	done_check_user_identifier_available_internally(server_output)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, SdkError>
{
	register_internally(user_identifier, password)
}

pub fn done_register(server_output: &str) -> Result<UserId, SdkError>
{
	done_register_internally(server_output)
}

pub fn prepare_login_start(user_id: &str) -> Result<String, SdkError>
{
	prepare_login_start_internally(user_id)
}

pub fn prepare_login(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, DeriveMasterKeyForAuth), SdkError>
{
	prepare_login_internally(user_identifier, password, server_output)
}

pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &str) -> Result<UserData, SdkError>
{
	done_login_internally(&master_key_encryption, server_output)
}

pub fn change_password(old_pw: &str, new_pw: &str, server_output_prep_login: &str, server_output_done_login: &str) -> Result<String, SdkError>
{
	change_password_internally(old_pw, new_pw, server_output_prep_login, server_output_done_login)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, SdkError>
{
	prepare_user_identifier_update_internally(user_identifier)
}

pub fn prepare_refresh_jwt(refresh_token: &str) -> Result<String, SdkError>
{
	prepare_refresh_jwt_internally(refresh_token)
}

pub fn reset_password(new_password: &str, decrypted_private_key: &PrivateKeyFormat, decrypted_sign_key: &SignKeyFormat) -> Result<String, SdkError>
{
	reset_password_internally(new_password, decrypted_private_key, decrypted_sign_key)
}

pub fn prepare_update_user_keys(password: &str, server_output: &MultipleLoginServerOutput) -> Result<Vec<KeyData>, SdkError>
{
	prepare_update_user_keys_internally(password, server_output)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use sentc_crypto_common::user::{ChangePasswordData, RegisterData};
	use sentc_crypto_core::Sk;

	use super::*;
	use crate::user::test_fn::{simulate_server_done_login, simulate_server_prepare_login};

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		std::println!("rust: {}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		let out = RegisterData::from_string(out.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, master_key_encryption_key) = prepare_login(username, password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

		let private_key = match login_out.keys.private_key.key {
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
		let username = "admin";
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(username, password).unwrap();

		let out_new = RegisterData::from_string(out.as_str()).unwrap();
		let out_old = RegisterData::from_string(out.as_str()).unwrap();

		let prep_server_output = simulate_server_prepare_login(&out_new.derived);
		let done_server_output = simulate_server_done_login(out_new);

		let pw_change_out = change_password(
			password,
			new_password,
			prep_server_output.as_str(),
			done_server_output.as_str(),
		)
		.unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_str()).unwrap();

		assert_ne!(
			pw_change_out.new_client_random_value,
			out_old.derived.client_random_value
		);

		assert_ne!(
			pw_change_out.new_encrypted_master_key,
			out_old.master_key.encrypted_master_key
		);
	}
}
