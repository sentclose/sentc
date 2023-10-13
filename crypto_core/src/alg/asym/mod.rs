use crate::{ECIES_OUTPUT, KYBER_OUTPUT};

pub(crate) mod ecies;
pub(crate) mod pqc_kyber;

pub enum Pk
{
	Ecies([u8; 32]),
	Kyber([u8; 1568]),
}

pub enum Sk
{
	Ecies([u8; 32]),
	Kyber([u8; 3168]),
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
		Sk::Kyber(_) => KYBER_OUTPUT,
	}
}

pub fn getting_alg_from_public_key(key: &Pk) -> &'static str
{
	match key {
		Pk::Ecies(_) => ECIES_OUTPUT,
		Pk::Kyber(_) => KYBER_OUTPUT,
	}
}
