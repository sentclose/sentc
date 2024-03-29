use ::pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};

use crate::{ECIES_KYBER_HYBRID_OUTPUT, ECIES_OUTPUT, KYBER_OUTPUT};

pub(crate) mod ecies;
pub(crate) mod ecies_kyber_hybrid;
pub(crate) mod pqc_kyber;

#[allow(clippy::large_enum_variant)]
pub enum Pk
{
	Ecies([u8; 32]),
	Kyber([u8; KYBER_PUBLICKEYBYTES]),
	EciesKyberHybrid
	{
		x: [u8; 32],
		k: [u8; KYBER_PUBLICKEYBYTES],
	},
}

#[allow(clippy::large_enum_variant)]
pub enum Sk
{
	Ecies([u8; 32]),
	Kyber([u8; KYBER_SECRETKEYBYTES]),
	EciesKyberHybrid
	{
		x: [u8; 32],
		k: [u8; KYBER_SECRETKEYBYTES],
	},
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
		Sk::EciesKyberHybrid {
			..
		} => ECIES_KYBER_HYBRID_OUTPUT,
	}
}

pub fn getting_alg_from_public_key(key: &Pk) -> &'static str
{
	match key {
		Pk::Ecies(_) => ECIES_OUTPUT,
		Pk::Kyber(_) => KYBER_OUTPUT,
		Pk::EciesKyberHybrid {
			..
		} => ECIES_KYBER_HYBRID_OUTPUT,
	}
}
