use sendclose_crypto::{aes, ecdh};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn aes_test()
{
	aes();
}

#[wasm_bindgen]
pub fn ed_test()
{
	ecdh();
}
