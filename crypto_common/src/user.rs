use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

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

/**
# Register Data for the server api

send this after register to the server
*/
#[derive(Serialize, Deserialize)]
pub struct RegisterData
{
	pub master_key: MasterKey,
	pub derived: KeyDerivedData,
}

impl RegisterData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<RegisterData>
	{
		//called from server

		from_slice::<Self>(v)
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
	pub fn from_string(v: &[u8]) -> serde_json::Result<ChangePasswordData>
	{
		from_slice::<Self>(v)
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

	pub fn from_string(v: &[u8]) -> serde_json::Result<ResetPasswordData>
	{
		from_slice::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub struct PrepareLoginData
{
	pub auth_key: String,
	pub master_key_encryption_key: MasterKeyFormat,
}

impl PrepareLoginData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<PrepareLoginData>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

//as base64 encoded string from the server
#[derive(Serialize, Deserialize)]
pub struct DoneLoginInput
{
	pub encrypted_master_key: String,
	pub encrypted_private_key: String,
	pub public_key_string: String,
	pub keypair_encrypt_alg: String,
	pub encrypted_sign_key: String,
	pub verify_key_string: String,
	pub keypair_sign_alg: String,
	pub keypair_encrypt_id: String,
	pub keypair_sign_id: String,
}

impl DoneLoginInput
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		//called from server
		to_string(self)
	}

	pub fn from_string(v: &[u8]) -> serde_json::Result<DoneLoginInput>
	{
		from_slice::<Self>(v)
	}
}

#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String),
}

impl MasterKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<MasterKeyFormat>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum PrivateKeyFormat
{
	Ecies(String),
}

impl PrivateKeyFormat
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
pub enum PublicKeyFormat
{
	Ecies(String),
}

impl PublicKeyFormat
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
pub enum SignKeyFormat
{
	Ed25519(String),
}

impl SignKeyFormat
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
pub enum VerifyKeyFormat
{
	Ed25519(String),
}

impl VerifyKeyFormat
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
pub struct KeyData
{
	pub private_key: PrivateKeyFormat,
	pub public_key: PublicKeyFormat,
	pub sign_key: SignKeyFormat,
	pub verify_key: VerifyKeyFormat,
	pub keypair_encrypt_id: String,
	pub keypair_sign_id: String,
}

impl KeyData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<KeyData>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}
