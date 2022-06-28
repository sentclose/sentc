use sendclose_crypto::{aes, argon, ecdh, sign};
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
