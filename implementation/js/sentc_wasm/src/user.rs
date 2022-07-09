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
pub fn register(password: String) -> String
{
	register_core(password.as_str())
}

#[wasm_bindgen]
pub fn prepare_login(password: String, server_output: String) -> String
{
	prepare_login_core(password.as_str(), server_output.as_str())
}

#[wasm_bindgen]
pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> String
{
	done_login_core(master_key_encryption.as_str(), server_output.as_str())
}

#[wasm_bindgen]
pub fn change_password(
	old_password: String,
	new_password: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> String
{
	change_password_core(
		old_password.as_str(),
		new_password.as_str(),
		old_salt.as_str(),
		encrypted_master_key.as_str(),
		derived_encryption_key_alg.as_str(),
	)
}

#[wasm_bindgen]
pub fn reset_password(new_password: String, decrypted_private_key: String, decrypted_sign_key: String) -> String
{
	reset_password_core(new_password.as_str(), decrypted_private_key.as_str(), decrypted_sign_key.as_str())
}
