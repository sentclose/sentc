use alloc::string::String;

use sentc_crypto_common::content_sortable::SortableEncryptOutput;
use sentc_crypto_core::cryptomat::SortableKey as CoreSort;
use sentc_crypto_utils::cryptomat::SortableKeyWrapper;
use sentc_crypto_utils::keys::SortableKey;

use crate::SdkError;

pub fn encrypt_raw_number(key: &str, data: u64) -> Result<u64, String>
{
	let key: SortableKey = key.parse()?;
	Ok(key.encrypt_sortable(data).map_err(Into::<SdkError>::into)?)
}

pub fn encrypt_number(key: &str, data: u64) -> Result<SortableEncryptOutput, String>
{
	let key: SortableKey = key.parse()?;
	Ok(key.encrypt_number(data)?)
}

pub fn encrypt_raw_string(key: &str, data: &str, max_len: Option<usize>) -> Result<u64, String>
{
	let key: SortableKey = key.parse()?;
	Ok(key.encrypt_raw_string(data, max_len)?)
}

pub fn encrypt_string(key: &str, data: &str, max_len: Option<usize>) -> Result<SortableEncryptOutput, String>
{
	let key: SortableKey = key.parse()?;
	Ok(key.encrypt_string(data, max_len)?)
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::group::test_fn::create_group_export;
	use crate::user::test_fn::create_user_export;

	extern crate std;

	#[test]
	fn test_simple()
	{
		let user = create_user_export();
		let (_, _, _, _, sortable_keys) = create_group_export(&user.user_keys[0]);

		let key = &sortable_keys[0];

		let values = ["a", "az", "azzz", "b", "ba", "baaa", "o", "oe", "z", "zaaa"];

		let mut encrypted_vars = [0u64; 10];

		for (i, value) in values.iter().enumerate() {
			encrypted_vars[i] = encrypt_raw_string(key, value, None).unwrap();
		}

		//check
		let mut past_item = 0;

		for item in encrypted_vars {
			assert!(past_item < item);

			past_item = item;
		}
	}

	#[test]
	fn test_with_generated_key()
	{
		const KEY: &str = r#"{"Ope16":{"key":"5kGPKgLQKmuZeOWQyJ7vOg==","key_id":"1876b629-5795-471f-9704-0cac52eaf9a1"}}"#;

		let a = encrypt_raw_number(KEY, 262).unwrap();
		let b = encrypt_raw_number(KEY, 263).unwrap();
		let c = encrypt_raw_number(KEY, 65321).unwrap();

		std::println!("a: {a}, b: {b}, c: {c}");

		assert!(a < b);
		assert!(b < c);

		assert_eq!(a, 17455249);
		assert_eq!(b, 17488544);
		assert_eq!(c, 4280794268);
	}
}
