use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::MultipleLoginServerOutput;
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

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
use crate::util::{
	export_private_key_to_string,
	export_public_key_to_string,
	export_sign_key_to_string,
	export_verify_key_to_string,
	import_private_key,
	import_sign_key,
	KeyData,
	KeyDataInt,
	UserData,
	UserDataInt,
};
use crate::SdkError;

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

pub fn register(user_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(register_internally(user_identifier, password)?)
}

pub fn done_register(server_output: &str) -> Result<UserId, String>
{
	Ok(done_register_internally(server_output)?)
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
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	))
}

pub fn done_login(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<UserData, String>
{
	let master_key_encryption = MasterKeyFormat::from_string(master_key_encryption).map_err(|e| SdkError::JsonParseFailed(e))?;

	let master_key_encryption = match master_key_encryption {
		MasterKeyFormat::Argon2(mk) => {
			let mk = Base64::decode_vec(mk.as_str()).map_err(|_e| SdkError::KeyDecryptFailed)?;

			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = mk.try_into().map_err(|_e| SdkError::KeyDecryptFailed)?;

			DeriveMasterKeyForAuth::Argon2(master_key_encryption_key)
		},
	};

	let result = done_login_internally(&master_key_encryption, server_output)?;

	export_user_data(result)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, String>
{
	Ok(prepare_user_identifier_update_internally(user_identifier)?)
}

pub fn prepare_refresh_jwt(refresh_token: &str) -> Result<String, String>
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

pub fn reset_password(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	let decrypted_private_key = import_private_key(decrypted_private_key)?;

	let decrypted_sign_key = import_sign_key(decrypted_sign_key)?;

	Ok(reset_password_internally(
		new_password,
		&decrypted_private_key,
		&decrypted_sign_key,
	)?)
}

pub fn prepare_update_user_keys(password: &str, server_output: &str) -> Result<String, String>
{
	let server_output = MultipleLoginServerOutput::from_string(server_output).map_err(|e| SdkError::JsonParseFailed(e))?;

	let out = prepare_update_user_keys_internally(password, &server_output)?;

	let mut output_arr = Vec::with_capacity(out.len());

	for result in out {
		//like done login but for all keys
		let output = export_key_data(result)?;

		output_arr.push(output);
	}

	//now this keys can be used to new encrypt the old content
	Ok(to_string(&output_arr).map_err(|_e| SdkError::JsonToStringFailed)?)
}

fn export_user_data(user_data: UserDataInt) -> Result<UserData, String>
{
	let jwt = user_data.jwt;
	let refresh_token = user_data.refresh_token;
	let user_id = user_data.user_id;

	let keys = export_key_data(user_data.keys)?;

	Ok(UserData {
		keys,
		jwt,
		refresh_token,
		user_id,
	})
}

fn export_key_data(key_data: KeyDataInt) -> Result<KeyData, String>
{
	let private_key = export_private_key_to_string(key_data.private_key)?;
	//the public key was decode from pem before by the done_login_internally function, so we can import it later one without checking err
	let public_key = export_public_key_to_string(key_data.public_key)?;
	let sign_key = export_sign_key_to_string(key_data.sign_key)?;
	let verify_key = export_verify_key_to_string(key_data.verify_key)?;

	Ok(KeyData {
		private_key,
		public_key,
		sign_key,
		verify_key,
		exported_public_key: key_data
			.exported_public_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
		exported_verify_key: key_data
			.exported_verify_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	})
}

#[cfg(test)]
mod test
{
	extern crate std;

	use sentc_crypto_common::user::{ChangePasswordData, RegisterData};

	use super::*;
	use crate::user::test_fn::{simulate_server_done_login, simulate_server_prepare_login};
	use crate::util::PrivateKeyFormat;

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		std::println!("{}", out);
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
		let (_auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(
			master_key_encryption_key.as_str(), //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		let private_key = match PrivateKeyFormat::from_string(login_out.keys.private_key.as_str()).unwrap() {
			PrivateKeyFormat::Ecies {
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
