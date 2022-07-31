use crate::ECIES_OUTPUT;

pub(crate) mod ecies;

pub enum Pk
{
	Ecies([u8; 32]),
}

pub enum Sk
{
	Ecies([u8; 32]),
}

pub(crate) struct AsymKeyOutput
{
	pub pk: Pk,
	pub sk: Sk,
	pub alg: &'static str,
}

pub fn getting_alg_from_private_key(key: &Sk) -> &'static str
{
	match key {
		Sk::Ecies(_) => ECIES_OUTPUT,
	}
}

pub fn getting_alg_from_public_key(key: &Pk) -> &'static str
{
	match key {
		Pk::Ecies(_) => ECIES_OUTPUT,
	}
}
