use alloc::vec::Vec;

pub(crate) mod argon2;

pub struct MasterKeyInfo
{
	pub encrypted_master_key: Vec<u8>,
	pub alg: &'static str, //describe how the master key is encrypted
}

pub enum ClientRandomValue
{
	Argon2([u8; 16]),
}

pub enum HashedAuthenticationKey
{
	Argon2([u8; 16]), //16 bytes of the org. hashed key
}

pub struct DeriveKeyOutput
{
	pub client_random_value: ClientRandomValue,
	pub hashed_authentication_key_bytes: HashedAuthenticationKey,
	pub master_key_info: MasterKeyInfo,
	pub alg: &'static str,
}

pub enum DeriveMasterKeyForAuth
{
	Argon2([u8; 32]),
}

pub enum DeriveAuthKeyForAuth
{
	Argon2([u8; 32]),
}

pub struct DeriveKeysForAuthOutput
{
	pub master_key_encryption_key: DeriveMasterKeyForAuth,
	pub auth_key: DeriveAuthKeyForAuth,
}

pub enum PasswordEncryptSalt
{
	Argon2([u8; 16]),
}

pub struct PasswordEncryptOutput
{
	pub salt: PasswordEncryptSalt,
	pub alg: &'static str,
}
