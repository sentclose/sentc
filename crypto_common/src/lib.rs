#![no_std]

extern crate alloc;

pub mod group;
pub mod user;

use alloc::string::String;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize)]
pub enum SymKeyFormat
{
	Aes(String),
}

impl SymKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		//this function is used internally
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}
