use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{DoneLoginServerKeysOutput, MultipleLoginServerOutput, PrepareLoginSaltServerOutput};
use sentc_crypto_core::{DeriveMasterKeyForAuth, Error};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::err_to_msg;
use crate::user::{
	change_password_internally,
	done_login_internally,
	prepare_login_internally,
	prepare_update_user_keys_internally,
	register_internally,
	reset_password_internally,
};
use crate::util::{export_private_key, export_public_key, export_sign_key, export_verify_key, import_private_key, import_sign_key, KeyData};

#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String),
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

#[derive(Serialize, Deserialize)]
pub struct PrepareLoginData
{
	pub auth_key: String,
	pub master_key_encryption_key: MasterKeyFormat,
}

impl PrepareLoginData
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

pub fn register(password: &str) -> Result<String, String>
{
	register_internally(password).map_err(|e| err_to_msg(e))
}

pub fn prepare_login(password: &str, server_output: &str) -> Result<String, String>
{
	let server_output = PrepareLoginSaltServerOutput::from_string(server_output).map_err(|_e| err_to_msg(Error::JsonParseFailed))?;

	let (auth_key, master_key_encryption_key) = prepare_login_internally(password, &server_output).map_err(|e| err_to_msg(e))?;

	//return the encryption key for the master key to the app and then use it for done login
	let master_key_encryption_key = match master_key_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => {
			let key = Base64::encode_string(&k);

			MasterKeyFormat::Argon2(key)
		},
	};

	let output = PrepareLoginData {
		auth_key,
		master_key_encryption_key,
	};

	output
		.to_string()
		.map_err(|_e| err_to_msg(Error::JsonToStringFailed))
}

pub fn done_login(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<String, String>
{
	let master_key_encryption = MasterKeyFormat::from_string(master_key_encryption).map_err(|_e| err_to_msg(Error::JsonParseFailed))?;

	let master_key_encryption = match master_key_encryption {
		MasterKeyFormat::Argon2(mk) => {
			let mk = Base64::decode_vec(mk.as_str()).map_err(|_e| err_to_msg(Error::KeyDecryptFailed))?;

			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = mk
				.try_into()
				.map_err(|_e| err_to_msg(Error::KeyDecryptFailed))?;

			DeriveMasterKeyForAuth::Argon2(master_key_encryption_key)
		},
	};

	let server_output = DoneLoginServerKeysOutput::from_string(server_output).map_err(|_| err_to_msg(Error::LoginServerOutputWrong))?;

	let result = done_login_internally(&master_key_encryption, &server_output).map_err(|e| err_to_msg(e))?;

	let private_key = export_private_key(result.private_key);
	//the public key was decode from pem before by the done_login_internally function, so we can import it later one without checking err
	let public_key = export_public_key(result.public_key);
	let sign_key = export_sign_key(result.sign_key);
	let verify_key = export_verify_key(result.verify_key);

	let output = KeyData {
		private_key,
		sign_key,
		public_key,
		verify_key,
	};

	output
		.to_string()
		.map_err(|_e| err_to_msg(Error::JsonToStringFailed))
}

pub fn change_password(
	old_pw: &str,
	new_pw: &str,
	old_salt: &str,
	encrypted_master_key: &str,
	derived_encryption_key_alg: &str,
) -> Result<String, String>
{
	change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg).map_err(|e| err_to_msg(e))
}

pub fn reset_password(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	let decrypted_private_key = import_private_key(decrypted_private_key).map_err(|e| err_to_msg(e))?;

	let decrypted_sign_key = import_sign_key(decrypted_sign_key).map_err(|e| err_to_msg(e))?;

	reset_password_internally(new_password, &decrypted_private_key, &decrypted_sign_key).map_err(|e| err_to_msg(e))
}

pub fn prepare_update_user_keys(password: &str, server_output: &str) -> Result<String, String>
{
	let server_output = MultipleLoginServerOutput::from_string(server_output).map_err(|_e| err_to_msg(Error::JsonParseFailed))?;

	let out = prepare_update_user_keys_internally(password, &server_output).map_err(|e| err_to_msg(e))?;

	let mut output_arr = Vec::with_capacity(out.len());

	for result in out {
		//like done login but for all keys

		let private_key = export_private_key(result.private_key);
		//the public key was decode from pem before by the done_login_internally function, so we can import it later one without checking err
		let public_key = export_public_key(result.public_key);
		let sign_key = export_sign_key(result.sign_key);
		let verify_key = export_verify_key(result.verify_key);

		let output = KeyData {
			private_key,
			sign_key,
			public_key,
			verify_key,
		};

		output_arr.push(output);
	}

	//now this keys can be used to new encrypt the old content
	to_string(&output_arr).map_err(|_e| err_to_msg(Error::JsonToStringFailed))
}

#[cfg(test)]
mod test
{
	extern crate std;

	use sentc_crypto_common::user::{ChangePasswordData, RegisterData};

	use super::*;
	use crate::user::test_fn::{simulate_server_done_login_as_string, simulate_server_prepare_login};
	use crate::util::PrivateKeyFormat;

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password).unwrap();

		std::println!("{}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let password = "abc*èéöäüê";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.derived)
			.to_string()
			.unwrap();

		//back to the client, send prep login out string to the server if it is no err
		let prep_login_out = prepare_login(password, server_output.as_str()).unwrap();

		//and get the master_key_encryption_key for done login
		let prep_login_out = PrepareLoginData::from_string(&prep_login_out.as_str()).unwrap();
		let master_key_encryption_key = prep_login_out.master_key_encryption_key;

		let server_output = simulate_server_done_login_as_string(out);

		//now save the values
		let login_out = done_login(
			master_key_encryption_key.to_string().unwrap().as_str(), //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		let login_out = KeyData::from_string(&login_out.as_str()).unwrap();

		let private_key = match login_out.private_key {
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
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_str()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		let pw_change_out = change_password(
			password,
			new_password,
			salt_from_rand_value.salt_string.as_str(),
			out.master_key.encrypted_master_key.as_str(),
			out.derived.derived_alg.as_str(),
		)
		.unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_str()).unwrap();

		assert_ne!(pw_change_out.new_client_random_value, out.derived.client_random_value);

		assert_ne!(pw_change_out.new_encrypted_master_key, out.master_key.encrypted_master_key);
	}
}
