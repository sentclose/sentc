use alloc::string::String;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize)]
pub struct SignHead
{
	pub id: String,
	pub alg: String, //in case at decrypt the user got no access to the verify key, but we still need to split data and sig
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedHead
{
	pub id: String,
	pub sign: Option<SignHead>, //the key id of the sign key
}

impl EncryptedHead
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}