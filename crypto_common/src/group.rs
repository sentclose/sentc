use alloc::string::String;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize)]
pub struct CreateData
{
	pub encrypted_group_key: String,
	pub group_key_alg: String,
	pub encrypted_group_key_alg: String,
	pub encrypted_private_group_key: String,
	pub public_group_key: String,
	pub keypair_encrypt_alg: String,
	pub creator_public_key_id: String,
}

impl CreateData
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

#[derive(Serialize, Deserialize)]
pub struct KeyRotationData
{
	pub encrypted_group_key_by_user: String, //encrypted by invoker public key
	pub group_key_alg: String,
	pub encrypted_group_key_alg: String, //info about how the encrypted group key was encrypted by the pk from the invoker (important for the server)
	pub encrypted_private_group_key: String,
	pub public_group_key: String,
	pub keypair_encrypt_alg: String,
	pub encrypted_group_key_by_ephemeral: String,
	pub ephemeral_alg: String,
	pub encrypted_ephemeral_key: String, //encrypted by the old group key. encrypt this key with every other member public key on the server
	pub previous_group_key_id: String,
	pub invoker_public_key_id: String,
}

impl KeyRotationData
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

#[derive(Serialize, Deserialize)]
pub struct KeyRotationInput
{
	pub encrypted_ephemeral_key_by_group_key_and_public_key: String,
	pub encrypted_group_key_by_ephemeral: String,
	pub ephemeral_alg: String,
	pub previous_group_key_id: String, //use this in the client sdk to load the right group key from the storage
}

impl KeyRotationInput
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

#[derive(Serialize, Deserialize)]
pub struct DoneKeyRotationData
{
	pub encrypted_new_group_key: String,
	pub public_key_id: String,
}

impl DoneKeyRotationData
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
