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
	server_output: String,
) -> String
{
	done_login_core(master_key_encryption, server_output)
}
