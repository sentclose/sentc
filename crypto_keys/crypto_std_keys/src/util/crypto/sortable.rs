use alloc::string::{String, ToString};
use core::cmp::Ordering;

use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_core::cryptomat::{CryptoAlg, SortableKey as CoreSortableI};
use sentc_crypto_utils::cryptomat::SortableKeyWrapper;
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::sortable_composer;

use crate::core::SortKeys as CoreSortableKey;
use crate::util::SortableKey;

sortable_composer!(SortableKey, CoreSortableKey);

impl SortableKeyWrapper for SortableKey
{
	type Inner = CoreSortableKey;

	fn get_id(&self) -> &str
	{
		&self.key_id
	}

	fn get_key(&self) -> &Self::Inner
	{
		&self.key
	}

	fn encrypt_raw_string(&self, data: &str, max_len: Option<usize>) -> Result<u64, SdkUtilError>
	{
		let n = Self::prepare_string(data, max_len.unwrap_or(4));

		Ok(self.key.encrypt_sortable(n)?)
	}

	fn encrypt_string(&self, data: &str, max_len: Option<usize>) -> Result<SortableEncryptOutput, SdkUtilError>
	{
		let number = self.encrypt_raw_string(data, max_len)?;

		Ok(SortableEncryptOutput {
			number,
			alg: self.key.get_alg_str().to_string(),
			key_id: self.key_id.clone(),
		})
	}
}

impl SortableKey
{
	fn transform_string_to_number(s: &str) -> u64
	{
		let mut number: u64 = 0;

		for c in s.chars() {
			let ascii_value = c as u64;
			number = number * 256 + ascii_value;
		}

		number / (u16::MAX as u64 - 1)
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
}
