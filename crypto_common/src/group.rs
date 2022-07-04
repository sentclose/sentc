use alloc::string::String;
use alloc::vec::Vec;

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
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

/**
# the current keys of a group

contains:
- encrypted group key
- encrypted private group (e.g. for sub group)
- public key
- and which public key was used to encrypt the group key

A group can have multiple of these structs for each key rotation
*/
#[derive(Serialize, Deserialize)]
pub struct GroupKeyServerOutput
{
	pub encrypted_group_key: String,
	pub group_key_alg: String,
	pub group_key_id: String,
	pub encrypted_private_group_key: String,
	pub public_group_key: String,
	pub keypair_encrypt_alg: String,
	pub key_pair_id: String,
	pub user_public_key_id: String, //to know what private key we should use to decrypt
}

impl GroupKeyServerOutput
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

/**
# The data about the group from the server

save this in the sdk impl storage
*/
#[derive(Serialize, Deserialize)]
pub struct GroupServerData
{
	pub group_id: String,
	pub keys: Vec<GroupKeyServerOutput>,
	pub keys_page: i32, //when returning the keys as pagination
}

impl GroupServerData
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

#[derive(Serialize, Deserialize)]
pub struct GroupKeysForNewMember
{
	pub encrypted_group_key: String, //base64 encoded
	pub alg: String,                 //the group key alg
	pub key_id: String,
	pub user_public_key_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct GroupKeysForNewMemberServerInput(pub Vec<GroupKeysForNewMember>);

impl GroupKeysForNewMemberServerInput
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