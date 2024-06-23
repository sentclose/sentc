use openssl::pkey::{HasPrivate, PKey};
use sentc_crypto_core::Error;

pub mod asym;
pub mod hmac;
pub mod pw_hash;
pub mod sign;
pub mod sortable;
pub mod sym;

fn export_sk<T: HasPrivate>(key: &PKey<T>) -> Result<Vec<u8>, Error>
{
	key.raw_private_key().map_err(|_e| Error::KeyCreationFailed)
}
