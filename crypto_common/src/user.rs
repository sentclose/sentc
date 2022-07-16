use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::{EncryptionKeyPairId, SignKeyPairId, SymKeyId, UserId};

#[derive(Serialize, Deserialize)]
pub struct MasterKey
{
	pub master_key_alg: String,
	pub encrypted_master_key: String, //base64 encoded master key
	pub encrypted_master_key_alg: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyDerivedData
{
	pub derived_alg: String,
	pub client_random_value: String, //don't use the enum for out, we will get the enum form the derived alg on the server (because the rand value is only used on the server)
	pub hashed_authentication_key: String,

	//pub/pri encrypt decrypt
	pub public_key: String,
	pub encrypted_private_key: String,
	pub keypair_encrypt_alg: String,

	//sign/verify
	pub verify_key: String,
	pub encrypted_sign_key: String,
	pub keypair_sign_alg: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserIdentifierAvailableServerInput
{
	pub user_identifier: String,
}

impl UserIdentifierAvailableServerInput
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
pub struct UserIdentifierAvailableServerOutput
{
	pub user_identifier: String,
	pub available: bool,
}

impl UserIdentifierAvailableServerOutput
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

/**
# Register Data for the server api

send this after register to the server
*/
#[derive(Serialize, Deserialize)]
pub struct RegisterData
{
	pub master_key: MasterKey,
	pub derived: KeyDerivedData,
	pub user_identifier: String, //with this the user is called for login. can be username or an id, or an email
}

impl RegisterData
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
pub struct ChangePasswordData
{
	pub new_derived_alg: String,
	pub new_client_random_value: String,
	pub new_hashed_authentication_key: String,
	pub new_encrypted_master_key: String,
	pub new_encrypted_master_key_alg: String,
	pub old_auth_key: String,
}

impl ChangePasswordData
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
pub struct ResetPasswordData
{
	pub client_random_value: String, //don't use the enum for out, we will get the enum form the derived alg on the server (because the rand value is only used on the server)
	pub hashed_authentication_key: String,
	pub master_key: MasterKey,
	pub derived_alg: String,
	pub encrypted_private_key: String,
	pub encrypted_sign_key: String,
}

impl ResetPasswordData
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub struct UserPublicKeyData
{
	pub public_key_pem: String,
	pub public_key_alg: String,
	pub public_key_id: EncryptionKeyPairId,
}

impl UserPublicKeyData
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
pub struct UserVerifyKeyData
{
	pub verify_key_pem: String,
	pub verify_key_alg: String,
	pub verify_key_id: SignKeyPairId,
}

impl UserVerifyKeyData
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
pub struct PrepareLoginServerInput
{
	pub user_identifier: String,
}

impl PrepareLoginServerInput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub struct PrepareLoginSaltServerOutput
{
	pub salt_string: String,
	pub derived_encryption_key_alg: String,
}

impl PrepareLoginSaltServerOutput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub struct DoneLoginServerInput
{
	pub auth_key: String,
}

impl DoneLoginServerInput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

//as base64 encoded string from the server
#[derive(Serialize, Deserialize)]
pub struct DoneLoginServerKeysOutput
{
	pub encrypted_master_key: String,
	pub encrypted_private_key: String,
	pub public_key_string: String,
	pub keypair_encrypt_alg: String,
	pub encrypted_sign_key: String,
	pub verify_key_string: String,
	pub keypair_sign_alg: String,
	pub keypair_encrypt_id: EncryptionKeyPairId,
	pub keypair_sign_id: SignKeyPairId,
	pub jwt: String,
}

impl DoneLoginServerKeysOutput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub struct PrepareLoginForKeyUpdateServerOutput
{
	pub client_random_value: String, //instead of prepare login (where the server creates the salt), for key update the client creates the salt for the old keys
	pub derived_encryption_key_alg: String,
	pub key_id: SymKeyId,
}

impl PrepareLoginForKeyUpdateServerOutput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}

/**
# Multiple login keys used

This is used to get all of the other keys of the user.
Just call prepare_login to get the derived key for the master key and then call done_login.
Call this right after login with the password.

This is only possible with a valid auth key.

This is only used for key update and only for the process of key update. So the usually max count is 2 (old and new).
Change or reset password are not possible in time of the key update.

<br>

## important!
Don't return this for the first login try. For the first login try just return the PrepareLoginSaltServerOutput of the latest keys!
 */
#[derive(Serialize, Deserialize)]
pub struct MultipleLoginServerOutput
{
	pub user_id: UserId,
	pub logins: Vec<PrepareLoginForKeyUpdateServerOutput>,
	pub done_logins: Vec<DoneLoginServerKeysOutput>,
}

impl MultipleLoginServerOutput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}

	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}
}
