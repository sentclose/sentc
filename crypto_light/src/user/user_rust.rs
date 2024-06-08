use alloc::string::String;

use sentc_crypto_common::user::UserDeviceRegisterInput;
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_core::DeriveMasterKeyForAuth;
use sentc_crypto_utils::user::{DeviceKeyDataInt, UserPreVerifyLogin};

use crate::error::SdkLightError;
use crate::user::{
	done_check_user_identifier_available_internally,
	done_register_device_start_internally,
	done_register_internally,
	done_validate_mfa_internally,
	generate_user_register_data_internally,
	prepare_check_user_identifier_available_internally,
	prepare_login_start_internally,
	prepare_refresh_jwt_internally,
	prepare_register_device_internally,
	prepare_register_device_private_internally,
	prepare_user_identifier_update_internally,
	register_internally,
	verify_login_internally,
};
use crate::UserDataInt;

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, SdkLightError>
{
	prepare_check_user_identifier_available_internally(user_identifier)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, SdkLightError>
{
	done_check_user_identifier_available_internally(server_output)
}

pub fn generate_user_register_data() -> Result<(String, String), SdkLightError>
{
	generate_user_register_data_internally()
}

pub fn register_typed(user_identifier: &str, password: &str) -> Result<UserDeviceRegisterInput, String>
{
	Ok(prepare_register_device_private_internally(user_identifier, password)?)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, SdkLightError>
{
	register_internally(user_identifier, password)
}

pub fn done_register(server_output: &str) -> Result<UserId, SdkLightError>
{
	done_register_internally(server_output)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), SdkLightError>
{
	done_register_device_start_internally(server_output)
}

pub fn prepare_register_device(server_output: &str) -> Result<String, SdkLightError>
{
	prepare_register_device_internally(server_output)
}

pub fn prepare_login_start(user_id: &str) -> Result<String, SdkLightError>
{
	prepare_login_start_internally(user_id)
}

pub fn done_validate_mfa(
	master_key_encryption: &DeriveMasterKeyForAuth,
	auth_key: String,
	device_identifier: String,
	server_output: &str,
) -> Result<UserPreVerifyLogin, SdkLightError>
{
	done_validate_mfa_internally(master_key_encryption, auth_key, device_identifier, server_output)
}

pub fn verify_login(server_output: &str, user_id: UserId, device_id: DeviceId, device_keys: DeviceKeyDataInt) -> Result<UserDataInt, SdkLightError>
{
	verify_login_internally(server_output, user_id, device_id, device_keys)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, SdkLightError>
{
	prepare_user_identifier_update_internally(user_identifier)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, SdkLightError>
{
	prepare_refresh_jwt_internally(refresh_token)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;

	use sentc_crypto_common::user::{ChangePasswordData, UserDeviceDoneRegisterInputLight, UserDeviceRegisterOutput};
	use sentc_crypto_common::ServerOutput;
	use serde_json::{from_str, to_string};

	use super::*;
	use crate::user::test_fn::{simulate_server_done_login, simulate_server_prepare_login, simulate_verify_login};
	use crate::user::{change_password, done_login, prepare_login};

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		std::println!("rust: {}", out);
	}

	#[test]
	fn test_register_with_generated_data()
	{
		let (username, password) = generate_user_register_data().unwrap();

		register(&username, &password).unwrap();
	}

	#[test]
	fn test_register_and_login()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		let out: UserDeviceRegisterInput = from_str(&out).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, auth_key, master_key_encryption_key) = prepare_login(username, password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(
			&master_key_encryption_key,
			auth_key,
			username.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(&login_out.challenge);
		let _login_out = verify_login(
			&server_output,
			login_out.user_id,
			login_out.device_id,
			login_out.device_keys,
		)
		.unwrap();
	}

	#[test]
	fn test_change_password()
	{
		let username = "admin";
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(username, password).unwrap();

		let out_new: UserDeviceRegisterInput = from_str(&out).unwrap();
		let out_old: UserDeviceRegisterInput = from_str(&out).unwrap();

		let prep_server_output = simulate_server_prepare_login(&out_new.derived);
		let done_server_output = simulate_server_done_login(out_new);

		let pw_change_out = change_password(password, new_password, &prep_server_output, done_server_output).unwrap();

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

	#[test]
	fn test_new_device()
	{
		//1. register the main device
		let out_string = register("hello", "1234").unwrap();
		let out: UserDeviceRegisterInput = from_str(&out_string).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived);
		let (_, auth_key, master_key_encryption_key) = prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let done_login_out = done_login(
			&master_key_encryption_key, //the value comes from prepare login
			auth_key,
			"hello".to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(&done_login_out.challenge);
		let _user = verify_login(
			&server_output,
			done_login_out.user_id,
			done_login_out.device_id,
			done_login_out.device_keys,
		)
		.unwrap();

		//2. prepare the device register
		let device_id = "hello_device";
		let device_pw = "12345";

		let server_input = register(device_id, device_pw).unwrap();

		//3. simulate server
		let input: UserDeviceRegisterInput = from_str(&server_input).unwrap();

		//4. server output
		let server_output = UserDeviceRegisterOutput {
			device_id: "abc".to_string(),
			token: "1234567890".to_string(),
			device_identifier: device_id.to_string(),
			public_key_string: input.derived.public_key.to_string(),
			keypair_encrypt_alg: input.derived.keypair_encrypt_alg.to_string(),
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_output),
		};

		let server_output = to_string(&server_output).unwrap();

		//5. check the server output
		done_register_device_start(&server_output).unwrap();

		//6. register the device with the main device

		let out = prepare_register_device(&server_output).unwrap();
		let _out: UserDeviceDoneRegisterInputLight = from_str(&out).unwrap();

		//7. check login with new device
		let server_output = simulate_server_prepare_login(&input.derived);
		let (_, auth_key, master_key_encryption_key) = prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(input);

		let new_device_data = done_login(
			&master_key_encryption_key,
			auth_key,
			device_id.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(&new_device_data.challenge);

		let _new_device_data = verify_login(
			&server_output,
			new_device_data.user_id,
			new_device_data.device_id,
			new_device_data.device_keys,
		)
		.unwrap();
	}
}
