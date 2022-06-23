pub(crate) mod argon2;

pub struct MasterKeyInfo
{
	pub encrypted_master_key: Vec<u8>,
	pub alg: &'static str,
}

pub struct DeriveKeyOutput
{
	pub client_random_value: [u8; 16],
	pub hashed_authentication_key_16bytes: [u8; 16],
	pub master_key_info: MasterKeyInfo,
	pub alg: &'static str,
}
