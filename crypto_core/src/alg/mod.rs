use alloc::vec::Vec;

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
