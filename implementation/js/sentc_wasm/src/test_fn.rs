use alloc::string::String;

use sentc_crypto::{group, test_fn, user, KeyData};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn register_test_full() -> String
{
	test_fn::register_test_full()
}

#[wasm_bindgen]
pub fn simulate_server_prepare_login(register_data: &str) -> String
{
	test_fn::simulate_server_prepare_login(register_data)
}

#[wasm_bindgen]
pub fn simulate_server_done_login(register_data: &str) -> String
{
	test_fn::simulate_server_done_login(register_data)
}

#[wasm_bindgen]
pub fn simulate_server_create_group(group_create_data: &str) -> String
{
	test_fn::simulate_server_create_group(group_create_data)
}

//user tests
#[wasm_bindgen]
pub struct PrepareLoginOutput
{
	auth_key: String,
	master_key_encryption_key: String,
}

#[wasm_bindgen]
impl PrepareLoginOutput
{
	pub fn get_auth_key(&self) -> String
	{
		self.auth_key.clone()
	}

	pub fn get_master_key_encryption_key(&self) -> String
	{
		self.master_key_encryption_key.clone()
	}
}

//define it here again because the filed must be private, so it can't be init from other mod
#[wasm_bindgen]
pub struct DoneLoginData1
{
	private_key: String, //Base64 exported keys
	public_key: String,
	sign_key: String,
	verify_key: String,
	jwt: String,
	user_id: String,
	exported_public_key: String,
	exported_verify_key: String,
}

impl From<KeyData> for DoneLoginData1
{
	fn from(keys: KeyData) -> Self
	{
		Self {
			private_key: keys.private_key,
			public_key: keys.public_key,
			sign_key: keys.sign_key,
			verify_key: keys.verify_key,
			jwt: keys.jwt,
			user_id: keys.user_id,
			exported_public_key: keys.exported_public_key,
			exported_verify_key: keys.exported_verify_key,
		}
	}
}

#[wasm_bindgen]
impl DoneLoginData1
{
	pub fn get_private_key(&self) -> String
	{
		self.private_key.clone()
	}

	pub fn get_public_key(&self) -> String
	{
		self.public_key.clone()
	}

	pub fn get_sign_key(&self) -> String
	{
		self.sign_key.clone()
	}

	pub fn get_verify_key(&self) -> String
	{
		self.verify_key.clone()
	}

	pub fn get_jwt(&self) -> String
	{
		self.jwt.clone()
	}

	pub fn get_id(&self) -> String
	{
		self.user_id.clone()
	}

	pub fn get_exported_public_key(&self) -> String
	{
		self.exported_public_key.clone()
	}

	pub fn get_exported_verify_key(&self) -> String
	{
		self.exported_verify_key.clone()
	}
}

#[wasm_bindgen]
pub fn register_test(username: &str, password: &str) -> Result<String, String>
{
	user::register(username, password)
}

#[wasm_bindgen]
pub fn prepare_login_test(username: &str, password: &str, server_output: &str) -> Result<PrepareLoginOutput, String>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(username, password, server_output)?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

#[wasm_bindgen]
pub fn done_login_test(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<DoneLoginData1, String>
{
	let keys = user::done_login(master_key_encryption, server_output)?;

	Ok(keys.into())
}

#[wasm_bindgen]
pub fn change_password_test(
	old_password: &str,
	new_password: &str,
	server_output_prep_login: &str,
	server_output_done_login: &str,
) -> Result<String, String>
{
	user::change_password(
		old_password,
		new_password,
		server_output_prep_login,
		server_output_done_login,
	)
}

#[wasm_bindgen]
pub fn reset_password_test(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	user::reset_password(new_password, decrypted_private_key, decrypted_sign_key)
}

//group tests

#[wasm_bindgen]
pub fn get_group_data_test(private_key: &str, server_output: &str) -> Result<String, String>
{
	let out = group::get_group_data(private_key, server_output)?;

	//return it as json string because rust wasm has problems with Vec<T> to convert to js array.
	Ok(out.to_string().map_err(|_| "Json to string failed")?)
}
