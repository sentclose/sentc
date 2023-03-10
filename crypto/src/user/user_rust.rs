use alloc::string::String;

use sentc_crypto_common::user::{RegisterData, UserPublicKeyData};
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;

use crate::user::{
	change_password_internally,
	done_check_user_identifier_available_internally,
	done_key_fetch_internally,
	done_login_internally,
	done_register_device_start_internally,
	done_register_internally,
	generate_user_register_data_internally,
	prepare_check_user_identifier_available_internally,
	prepare_login_internally,
	prepare_login_start_internally,
	prepare_refresh_jwt_internally,
	prepare_register_device_internally,
	prepare_register_device_start_internally,
	prepare_user_identifier_update_internally,
	register_internally,
	register_typed_internally,
	reset_password_internally,
};
use crate::util::{PrivateKeyFormat, SignKeyFormat, SymKeyFormat, UserData, UserKeyData};
use crate::SdkError;

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, SdkError>
{
	prepare_check_user_identifier_available_internally(user_identifier)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, SdkError>
{
	done_check_user_identifier_available_internally(server_output)
}

pub fn generate_user_register_data() -> Result<(String, String), SdkError>
{
	generate_user_register_data_internally()
}

pub fn register_typed(user_identifier: &str, password: &str) -> Result<RegisterData, String>
{
	Ok(register_typed_internally(user_identifier, password)?)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, SdkError>
{
	register_internally(user_identifier, password)
}

pub fn done_register(server_output: &str) -> Result<UserId, SdkError>
{
	done_register_internally(server_output)
}

pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, SdkError>
{
	prepare_register_device_start_internally(device_identifier, password)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), SdkError>
{
	done_register_device_start_internally(server_output)
}

pub fn prepare_register_device(server_output: &str, user_keys: &[&SymKeyFormat], key_session: bool) -> Result<(String, UserPublicKeyData), SdkError>
{
	prepare_register_device_internally(server_output, user_keys, key_session)
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
	let (result, hmac_keys) = done_login_internally(master_key_encryption, server_output)?;

	Ok(UserData {
		jwt: result.jwt,
		refresh_token: result.refresh_token,
		user_id: result.user_id,
		device_id: result.device_id,

		user_keys: result.user_keys,
		device_keys: result.device_keys,
		hmac_keys,
	})
}

pub fn done_key_fetch(private_key: &PrivateKeyFormat, server_output: &str) -> Result<UserKeyData, SdkError>
{
	done_key_fetch_internally(private_key, server_output)
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

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;

	use sentc_crypto_common::group::CreateData;
	use sentc_crypto_common::user::{
		ChangePasswordData,
		RegisterData,
		UserDeviceDoneRegisterInput,
		UserDeviceRegisterInput,
		UserDeviceRegisterOutput,
	};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::{Sk, SymKey};
	use serde_json::to_string;

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

		let out = RegisterData::from_string(out.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, master_key_encryption_key) = prepare_login(username, password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

		let private_key = match login_out.user_keys[0].private_key.key {
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

		let prep_server_output = simulate_server_prepare_login(&out_new.device.derived);
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
			out_old.device.derived.client_random_value
		);

		assert_ne!(
			pw_change_out.new_encrypted_master_key,
			out_old.device.master_key.encrypted_master_key
		);
	}

	#[test]
	fn test_new_device()
	{
		//1. register the main device
		let out_string = register("hello", "1234").unwrap();
		let out = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);
		let (_auth_key, master_key_encryption_key) = prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let user = done_login(
			&master_key_encryption_key, //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		//2. prepare the device register
		let device_id = "hello_device";
		let device_pw = "12345";

		let server_input = prepare_register_device_start(device_id, device_pw).unwrap();

		//3. simulate server
		let input: UserDeviceRegisterInput = serde_json::from_str(&server_input).unwrap();

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

		let (out, _) = prepare_register_device(&server_output, &[&user.user_keys[0].group_key], false).unwrap();

		let out: UserDeviceDoneRegisterInput = serde_json::from_str(&out).unwrap();
		let user_keys = &out.user_keys.keys[0];

		//7. check login with new device
		let out_new_device = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&input.derived);
		let (_auth_key, master_key_encryption_key) = prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(RegisterData {
			device: input,
			group: CreateData {
				encrypted_group_key: user_keys.encrypted_group_key.to_string(),
				group_key_alg: out_new_device.group.group_key_alg,
				encrypted_group_key_alg: user_keys.encrypted_alg.to_string(),

				//private and sign key are encrypted by group key and for all device the same
				encrypted_private_group_key: out_new_device.group.encrypted_private_group_key,
				public_group_key: out_new_device.group.public_group_key,
				keypair_encrypt_alg: out_new_device.group.keypair_encrypt_alg,
				creator_public_key_id: "abc".to_string(),
				encrypted_hmac_key: out_new_device.group.encrypted_hmac_key,
				encrypted_hmac_alg: out_new_device.group.encrypted_hmac_alg,
				encrypted_sign_key: out_new_device.group.encrypted_sign_key,
				verify_key: out_new_device.group.verify_key,
				keypair_sign_alg: out_new_device.group.keypair_sign_alg,
			},
		});

		let new_device_data = done_login(&master_key_encryption_key, server_output.as_str()).unwrap();

		match (
			&user.user_keys[0].group_key.key,
			&new_device_data.user_keys[0].group_key.key,
		) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(*k1, *k2);
			},
		}

		match (
			&user.device_keys.private_key.key,
			&new_device_data.device_keys.private_key.key,
		) {
			(Sk::Ecies(k1), Sk::Ecies(k2)) => {
				assert_ne!(*k1, *k2);
			},
		}
	}
}
