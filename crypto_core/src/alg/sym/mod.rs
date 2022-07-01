pub(crate) mod aes_gcm;

pub(crate) enum SymKey
{
	Aes([u8; 32]),
}

pub(crate) struct SymKeyOutput
{
	pub alg: &'static str,
	pub key: SymKey,
}
