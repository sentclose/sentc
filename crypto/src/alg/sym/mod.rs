pub(crate) mod aes_gcm;

pub enum SymKey
{
	Aes([u8; 32]),
}

pub struct SymKeyOutput
{
	pub alg: &'static str,
	pub key: SymKey,
}