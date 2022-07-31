use crate::AES_GCM_OUTPUT;

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

pub fn getting_alg_from_sym_key(key: &SymKey) -> &'static str
{
	match key {
		SymKey::Aes(_) => AES_GCM_OUTPUT,
	}
}
