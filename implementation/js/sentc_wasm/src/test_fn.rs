use alloc::string::String;

use sentc_crypto::{test_fn, user};
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
}

#[wasm_bindgen]
pub fn register_test(username: &str, password: &str) -> Result<String, String>
{
	user::register(username, password)
}

#[wasm_bindgen]
pub fn prepare_login_test(password: &str, server_output: &str) -> Result<PrepareLoginOutput, String>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(password, server_output)?;

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

	Ok(DoneLoginData1 {
		private_key: keys.private_key,
		public_key: keys.public_key,
		sign_key: keys.sign_key,
		verify_key: keys.verify_key,
		jwt: keys.jwt,
	})
}

#[wasm_bindgen]
pub fn change_password_test(
	old_password: &str,
	new_password: &str,
	old_salt: &str,
	encrypted_master_key: &str,
	derived_encryption_key_alg: &str,
) -> Result<String, String>
{
	user::change_password(old_password, new_password, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

#[wasm_bindgen]
pub fn reset_password_test(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	user::reset_password(new_password, decrypted_private_key, decrypted_sign_key)
}
