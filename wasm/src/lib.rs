use sendclose_crypto::{
	aes,
	argon,
	done_login as done_login_core,
	ecdh,
	prepare_login as prepare_login_core,
	register as register_core,
	register_test,
	sign,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn aes_test() -> String
{
	aes()
}

#[wasm_bindgen]
pub fn ed_test() -> String
{
	ecdh()
}

#[wasm_bindgen]
pub fn argon_test() -> String
{
	argon()
}

#[wasm_bindgen]
pub fn sign_test() -> String
{
	sign()
}

#[wasm_bindgen]
pub fn register_test_full() -> String
{
	register_test()
}

//real usage
#[wasm_bindgen]
pub fn register(password: String) -> String
{
	register_core(password)
}

#[wasm_bindgen]
pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> String
{
	prepare_login_core(password, salt_string, derived_encryption_key_alg)
}

#[wasm_bindgen]
pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	encrypted_master_key: String,  //as base64 encoded string from the server
	encrypted_private_key: String,
	public_key_string: String,
	keypair_encrypt_alg: String,
	encrypted_sign_key: String,
	verify_key_string: String,
	keypair_sign_alg: String,
) -> String
{
	done_login_core(
		master_key_encryption,
		encrypted_master_key,
		encrypted_private_key,
		public_key_string,
		keypair_encrypt_alg,
		encrypted_sign_key,
		verify_key_string,
		keypair_sign_alg,
	)
}
