use openssl::pkey::{HasPrivate, HasPublic, PKey};
use sentc_crypto_core::Error;

pub mod asym;
pub mod pw_hash;
pub mod sign;
pub mod sortable;

pub mod sym
{
	pub use sentc_crypto_fips_keys::core::sym::*;
}

pub mod hmac
{
	pub use sentc_crypto_fips_keys::core::hmac::*;
}

fn export_pk<T: HasPublic>(pk: &PKey<T>) -> Result<Vec<u8>, Error>
{
	pk.raw_public_key().map_err(|_e| Error::KeyCreationFailed)
}

fn export_sk<T: HasPrivate>(key: &PKey<T>) -> Result<Vec<u8>, Error>
{
	key.raw_private_key().map_err(|_e| Error::KeyCreationFailed)
}

#[macro_export]
macro_rules! import_export_pqc {
	($st:ty,$k:ident) => {
		impl AsRef<[u8]> for $st
		{
			fn as_ref(&self) -> &[u8]
			{
				self.0.as_bytes()
			}
		}

		impl TryFrom<Vec<u8>> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
			{
				Ok(Self(
					$k::from_bytes(&value).map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				))
			}
		}

		impl<'a> TryFrom<&'a [u8]> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
			{
				Ok(Self(
					$k::from_bytes(value).map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				))
			}
		}
	};
}

#[macro_export]
macro_rules! hybrid_import_export {
	($st:ty,$import_k:ident, $export_k:ident,$k:ident) => {
		impl $st
		{
			pub fn prepare_export(&self) -> Result<(Vec<u8>, &[u8]), sentc_crypto_core::Error>
			{
				Ok(($export_k(&self.x)?, self.k.as_bytes()))
			}

			pub fn from_bytes(bytes_x: &[u8], bytes_k: &[u8]) -> Result<Self, sentc_crypto_core::Error>
			{
				Ok(Self {
					x: $import_k(bytes_x)?,
					k: $k::from_bytes(bytes_k).map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				})
			}
		}
	};
}

#[macro_export]
macro_rules! hybrid_sk_from_bytes {
	($st:ty,$import_k:ident, $k:ident) => {
		impl $st
		{
			fn import(bytes: &[u8]) -> Result<Self, sentc_crypto_core::Error>
			{
				let x = &bytes[..32];
				let k = &bytes[32..];

				Ok(Self {
					x: $import_k(x)?,
					k: $k::from_bytes(k).map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				})
			}
		}

		impl<'a> TryFrom<&'a [u8]> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
			{
				Self::import(value)
			}
		}

		impl TryFrom<Vec<u8>> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
			{
				Self::import(&value)
			}
		}
	};
}
