#![no_std]

pub mod crypto;
pub mod group;
pub mod user;

extern crate alloc;

use alloc::string::String;

use sentc_crypto::test_fn;
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
