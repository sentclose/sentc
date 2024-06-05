pub(crate) mod asym;
pub(crate) mod hmac;
pub(crate) mod pw_hash;
pub(crate) mod sign;
pub(crate) mod sortable;
pub(crate) mod sym;

#[macro_export]
macro_rules! try_from_bytes_single_value {
	($st:ty) => {
		impl<'a> TryFrom<&'a [u8]> for $st
		{
			type Error = $crate::Error;

			fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
			{
				Ok(Self(
					value
						.try_into()
						.map_err(|_| $crate::Error::KeyDecryptFailed)?,
				))
			}
		}
	};
}

#[macro_export]
macro_rules! try_from_bytes_owned_single_value {
	($st:ty) => {
		impl TryFrom<Vec<u8>> for $st
		{
			type Error = $crate::Error;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
			{
				Ok(Self(
					value
						.try_into()
						.map_err(|_| $crate::Error::KeyDecryptFailed)?,
				))
			}
		}
	};
}

#[macro_export]
macro_rules! into_bytes_single_value {
	($st:ty) => {
		impl Into<Vec<u8>> for $st
		{
			fn into(self) -> Vec<u8>
			{
				Vec::from(self.0)
			}
		}
	};
}

#[macro_export]
macro_rules! as_ref_bytes_single_value {
	($st:ty) => {
		impl AsRef<[u8]> for $st
		{
			fn as_ref(&self) -> &[u8]
			{
				&self.0
			}
		}
	};
}

#[macro_export]
macro_rules! crypto_alg_str_impl {
	($st:ty,$alg:ident) => {
		impl CryptoAlg for $st
		{
			fn get_alg_str(&self) -> &'static str
			{
				$alg
			}
		}
	};
}

#[macro_export]
macro_rules! hybrid_key_import_export {
	($st:ty) => {
		impl $st
		{
			pub fn get_raw_keys(&self) -> (&[u8], &[u8])
			{
				(&self.x, &self.k)
			}

			pub fn from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self {
					x: bytes_x.try_into().map_err(|_| Error::KeyDecryptFailed)?,
					k: bytes_k.try_into().map_err(|_| Error::KeyDecryptFailed)?,
				})
			}
		}
	};
}
