use alloc::string::ToString;
use core::cmp::Ordering;

use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_core::cryptomat::{CryptoAlg, SortableKey as CoreSortableI};

use crate::error::SdkUtilError;
use crate::keys::SortableKey;

impl SortableKey
{
	fn transform_string_to_number(s: &str) -> u64
	{
		let mut number: u64 = 0;

		for c in s.chars() {
			let ascii_value = c as u64;
			number = number * 256 + ascii_value;
		}

		number / (u16::max_value() as u64 - 1)
	}

	fn prepare_string(data: &str, max_len: usize) -> u64
	{
		match data.len().cmp(&max_len) {
			Ordering::Greater => Self::transform_string_to_number(&data[..max_len]),
			Ordering::Less => {
				//fill it with dummy chars to get the len
				let mut st = data.to_string();

				for _i in data.len()..max_len {
					st += "*";
				}

				Self::transform_string_to_number(&st)
			},
			Ordering::Equal => Self::transform_string_to_number(data),
		}
	}

	pub fn encrypt_number(&self, data: u64) -> Result<SortableEncryptOutput, SdkUtilError>
	{
		let number = self.key.encrypt_sortable(data)?;

		Ok(SortableEncryptOutput {
			number,
			alg: self.key.get_alg_str().to_string(),
			key_id: self.key_id.clone(),
		})
	}

	pub fn encrypt_raw_string(&self, data: &str, max_len: Option<usize>) -> Result<u64, SdkUtilError>
	{
		let n = Self::prepare_string(data, max_len.unwrap_or(4));

		Ok(self.key.encrypt_sortable(n)?)
	}

	pub fn encrypt_string(&self, data: &str, max_len: Option<usize>) -> Result<SortableEncryptOutput, SdkUtilError>
	{
		let number = self.encrypt_raw_string(data, max_len)?;

		Ok(SortableEncryptOutput {
			number,
			alg: self.key.get_alg_str().to_string(),
			key_id: self.key_id.clone(),
		})
	}
}
