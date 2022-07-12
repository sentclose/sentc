use alloc::string::String;

use sentc_crypto::user::{
	change_password as change_password_core,
	done_login as done_login_core,
	prepare_login as prepare_login_core,
	register as register_core,
	reset_password as reset_password_core,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PrepareLoginOutput
{
	auth_key: String,
	master_key_encryption_key: String,
}

#[wasm_bindgen]
impl PrepareLoginOutput
{
	pub fn get_auth_key(self) -> String
	{
		self.auth_key
	}

	pub fn get_master_key_encryption_key(self) -> String
	{
		self.master_key_encryption_key
	}
}

#[wasm_bindgen]
pub fn register(password: &str) -> Result<String, String>
{
	register_core(password)
}

#[wasm_bindgen]
pub fn prepare_login(password: &str, server_output: &str) -> Result<PrepareLoginOutput, String>
{
	let (auth_key, master_key_encryption_key) = prepare_login_core(password, server_output)?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

#[wasm_bindgen]
pub fn done_login(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<String, String>
{
	done_login_core(master_key_encryption, server_output)
}

#[wasm_bindgen]
pub fn change_password(
	old_password: &str,
	new_password: &str,
	old_salt: &str,
	encrypted_master_key: &str,
	derived_encryption_key_alg: &str,
) -> Result<String, String>
{
	change_password_core(old_password, new_password, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

#[wasm_bindgen]
pub fn reset_password(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	reset_password_core(new_password, decrypted_private_key, decrypted_sign_key)
}
