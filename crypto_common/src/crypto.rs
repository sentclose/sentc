use alloc::string::String;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, from_str, to_string};

use crate::SignKeyPairId;

#[derive(Serialize, Deserialize)]
pub struct SignHead
{
	pub id: SignKeyPairId,
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
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn from_slice(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub struct GeneratedSymKeyHeadServerInput
{
	pub alg: String,
	pub encrypted_key_string: String,
	pub master_key_id: String,
}

impl GeneratedSymKeyHeadServerInput
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub struct GeneratedSymKeyHeadServerOutput
{
	pub alg: String,
	pub encrypted_key_string: String,
	pub master_key_id: String,
	pub key_id: String,
}

impl GeneratedSymKeyHeadServerOutput
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}
