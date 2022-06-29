pub(crate) mod argon2;

pub struct MasterKeyInfo
{
	pub encrypted_master_key: Vec<u8>,
	pub alg: &'static str,
}

pub enum ClientRandomValue
{
	Argon2([u8; 16]),
}

pub enum HashedAuthenticationKey
{
	Argon2([u8; 16]),
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
	master_key_encryption_key: DeriveMasterKeyForAuth,
	auth_key: DeriveAuthKeyForAuth,
}
