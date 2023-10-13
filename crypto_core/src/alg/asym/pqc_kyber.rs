use pqc_kyber::{keypair, PublicKey, SecretKey};
use rand_core::{CryptoRng, RngCore};

use crate::alg::asym::AsymKeyOutput;
use crate::{get_rand, Error, Pk, Sk};

pub const KYBER_OUTPUT: &str = "KYBER_1024";

pub(crate) fn generate_static_keypair() -> Result<AsymKeyOutput, Error>
{
	let (sk, pk) = generate_keypair_internally(&mut get_rand())?;

	Ok(AsymKeyOutput {
		alg: KYBER_OUTPUT,
		pk: Pk::Kyber(pk),
		sk: Sk::Kyber(sk),
	})
}

//__________________________________________________________________________________________________

fn generate_keypair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(SecretKey, PublicKey), Error>
{
	let keys = keypair(rng).map_err(|_| Error::KeyCreationFailed)?;

	Ok((keys.secret, keys.public))
}
