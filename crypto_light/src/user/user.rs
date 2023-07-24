use alloc::string::String;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::UserDeviceRegisterInput;
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::error::SdkLightError;
use crate::user::{
	change_password_internally,
	done_check_user_identifier_available_internally,
	done_login_internally,
	done_register_device_start_internally,
	done_register_internally,
	generate_user_register_data_internally,
	prepare_check_user_identifier_available_internally,
	prepare_login_internally,
	prepare_login_start_internally,
	prepare_refresh_jwt_internally,
	prepare_register_device_internally,
	prepare_register_device_private_internally,
	prepare_user_identifier_update_internally,
	register_internally,
};
use crate::UserDataExport;

#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String), //Base64 encoded string from prepare login, is used in done_login
}

impl MasterKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, String>
{
	Ok(prepare_check_user_identifier_available_internally(user_identifier)?)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, String>
{
	Ok(done_check_user_identifier_available_internally(server_output)?)
}

pub fn generate_user_register_data() -> Result<(String, String), String>
{
	Ok(generate_user_register_data_internally()?)
}

pub fn register_typed(device_identifier: &str, password: &str) -> Result<UserDeviceRegisterInput, String>
{
	Ok(prepare_register_device_private_internally(
		device_identifier,
		password,
	)?)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, String>
{
	//use register also for reset pw
	Ok(register_internally(user_identifier, password)?)
}

pub fn done_register(server_output: &str) -> Result<UserId, String>
{
	Ok(done_register_internally(server_output)?)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), String>
{
	Ok(done_register_device_start_internally(server_output)?)
}

pub fn prepare_register_device(server_output: &str) -> Result<String, String>
{
	Ok(prepare_register_device_internally(server_output)?)
}

pub fn prepare_login_start(user_id: &str) -> Result<String, String>
{
	Ok(prepare_login_start_internally(user_id)?)
}

pub fn prepare_login(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, String), String>
{
	//the auth key is already in the right json format for the server
	let (auth_key, master_key_encryption_key) = prepare_login_internally(user_identifier, password, server_output)?;

	//return the encryption key for the master key to the app and then use it for done login
	let master_key_encryption_key = match master_key_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => {
			let key = Base64::encode_string(&k);

			MasterKeyFormat::Argon2(key)
		},
	};

	Ok((
		auth_key,
		master_key_encryption_key
			.to_string()
			.map_err(|_e| SdkLightError::JsonToStringFailed)?,
	))
}

pub fn done_login(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<UserDataExport, String>
{
	let master_key_encryption = MasterKeyFormat::from_string(master_key_encryption).map_err(SdkLightError::JsonParseFailed)?;

	let master_key_encryption = match master_key_encryption {
		MasterKeyFormat::Argon2(mk) => {
			let mk = Base64::decode_vec(mk.as_str()).map_err(|_e| SdkLightError::KeyDecryptFailed)?;

			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = mk
				.try_into()
				.map_err(|_e| SdkLightError::KeyDecryptFailed)?;

			DeriveMasterKeyForAuth::Argon2(master_key_encryption_key)
		},
	};

	let result = done_login_internally(&master_key_encryption, server_output)?;

	Ok(result.try_into()?)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, String>
{
	Ok(prepare_user_identifier_update_internally(user_identifier)?)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, String>
{
	Ok(prepare_refresh_jwt_internally(refresh_token)?)
}

pub fn change_password(old_pw: &str, new_pw: &str, server_output_prep_login: &str, server_output_done_login: &str) -> Result<String, String>
{
	Ok(change_password_internally(
		old_pw,
		new_pw,
		server_output_prep_login,
		server_output_done_login,
	)?)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;

	use sentc_crypto_common::user::{ChangePasswordData, UserDeviceDoneRegisterInputLight, UserDeviceRegisterOutput};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_utils::keys::PrivateKeyFormatExport;

	use super::*;
	use crate::user::test_fn::{simulate_server_done_login, simulate_server_prepare_login};

	extern crate std;

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		std::println!("{}", out);
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

		let (_auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		let login_out = done_login(
			master_key_encryption_key.as_str(), //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		let private_key = match from_str(&login_out.device_keys.private_key).unwrap() {
			PrivateKeyFormatExport::Ecies {
				key_id: _,
				key,
			} => key,
		};

		assert_ne!(private_key, "");
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

	#[test]
	fn test_new_device()
	{
		//1. register the main device
		let out_string = register("hello", "1234").unwrap();
		let out: UserDeviceRegisterInput = from_str(&out_string).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived);

		let (_auth_key, master_key_encryption_key) = prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let user = done_login(
			master_key_encryption_key.as_str(), //the value comes from prepare login
			server_output.as_str(),
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

		let (_auth_key, master_key_encryption_key) = prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(input);

		let new_device_data = done_login(master_key_encryption_key.as_str(), server_output.as_str()).unwrap();

		assert_ne!(user.device_keys.private_key, new_device_data.device_keys.private_key);
	}
}
