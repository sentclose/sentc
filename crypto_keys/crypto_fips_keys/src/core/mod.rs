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

#[macro_export]
macro_rules! import_export_openssl {
	($st:ty,$import_k:ident, $export_k:ident) => {
		impl $st
		{
			pub fn export(&self) -> Result<Vec<u8>, Error>
			{
				$export_k(&self.0)
			}
		}

		impl TryFrom<Vec<u8>> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
			{
				Ok(Self($import_k(&value)?))
			}
		}

		impl<'a> TryFrom<&'a [u8]> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
			{
				Ok(Self($import_k(value)?))
			}
		}

		impl TryInto<Vec<u8>> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_into(self) -> Result<Vec<u8>, Self::Error>
			{
				$export_k(&self.0)
			}
		}
	};
}
