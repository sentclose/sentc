use alloc::string::ToString;
use core::cmp::Ordering;

use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_core::getting_alg_from_sortable_key;
use sentc_crypto_utils::keys::SortableKeyFormatInt;

use crate::SdkError;

#[cfg(not(feature = "rust"))]
mod crypto_sortable;
#[cfg(feature = "rust")]
mod crypto_sortable_rust;

#[cfg(not(feature = "rust"))]
pub use self::crypto_sortable::{encrypt_number, encrypt_raw_number, encrypt_raw_string, encrypt_string};
#[cfg(feature = "rust")]
pub use self::crypto_sortable_rust::{encrypt_number, encrypt_raw_number, encrypt_raw_string, encrypt_string};

fn encrypt_raw_number_internally(key: &SortableKeyFormatInt, data: u64) -> Result<u64, SdkError>
{
	Ok(sentc_crypto_core::crypto::encrypt_sortable(&key.key, data)?)
}
fn encrypt_number_internally(key: &SortableKeyFormatInt, data: u64) -> Result<SortableEncryptOutput, SdkError>
{
	let number = encrypt_raw_number_internally(key, data)?;

	Ok(SortableEncryptOutput {
		number,
		alg: getting_alg_from_sortable_key(&key.key).to_string(),
		key_id: key.key_id.clone(),
	})
}

fn encrypt_raw_string_internally(key: &SortableKeyFormatInt, data: &str) -> Result<u64, SdkError>
{
	let n = prepare_string(data, 4);

	encrypt_raw_number_internally(key, n)
}

fn encrypt_string_internally(key: &SortableKeyFormatInt, data: &str) -> Result<SortableEncryptOutput, SdkError>
{
	let number = encrypt_raw_string_internally(key, data)?;

	Ok(SortableEncryptOutput {
		number,
		alg: getting_alg_from_sortable_key(&key.key).to_string(),
		key_id: key.key_id.clone(),
	})
}

fn prepare_string(data: &str, max_len: usize) -> u64
{
	match data.len().cmp(&max_len) {
		Ordering::Greater => transform_string_to_number(&data[..max_len]),
		Ordering::Less => {
			//fill it with dummy chars to get the len
			let mut st = data.to_string();

			for _i in data.len()..max_len {
				st += "*";
			}

			transform_string_to_number(&st)
		},
		Ordering::Equal => transform_string_to_number(data),
	}
}

fn transform_string_to_number(s: &str) -> u64
{
	let mut number: u64 = 0;

	for c in s.chars() {
		let ascii_value = c as u64;
		number = number * 256 + ascii_value;
	}

	number / (u16::max_value() as u64 - 1)
}
