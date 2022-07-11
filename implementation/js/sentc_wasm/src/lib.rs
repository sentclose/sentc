#![no_std]

pub mod crypto;
pub mod group;
pub mod user;

extern crate alloc;

use alloc::string::String;

use sentc_crypto::register_test;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn register_test_full() -> String
{
	register_test()
}
