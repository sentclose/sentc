#[cfg(feature = "export")]
mod crypto_sortable_export;

#[cfg(feature = "export")]
pub use crypto_sortable_export::*;

#[cfg(all(test, any(feature = "std_keys", feature = "rec_keys")))]
mod test
{
	use core::str::FromStr;

	use sentc_crypto_core::cryptomat::SortableKey as CoreSort;
	use sentc_crypto_utils::cryptomat::SortableKeyWrapper;

	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	extern crate std;

	#[cfg(feature = "std_keys")]
	pub type TestKey = sentc_crypto_std_keys::util::SortableKey;
	#[cfg(all(feature = "rec_keys", not(feature = "std_keys")))]
	pub type TestKey = sentc_crypto_rec_keys::util::SortableKey;

	#[test]
	fn test_simple()
	{
		let user = create_user();
		let (_, _, _, _, sortable_keys) = create_group(&user.user_keys[0]);

		let key = &sortable_keys[0];

		let values = ["a", "az", "azzz", "b", "ba", "baaa", "o", "oe", "z", "zaaa"];

		let mut encrypted_vars = [0u64; 10];

		for (i, value) in values.iter().enumerate() {
			encrypted_vars[i] = key.encrypt_raw_string(value, None).unwrap();
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

		let a = TestKey::from_str(KEY)
			.unwrap()
			.key
			.encrypt_sortable(262)
			.unwrap();

		let b = TestKey::from_str(KEY)
			.unwrap()
			.key
			.encrypt_sortable(263)
			.unwrap();

		let c = TestKey::from_str(KEY)
			.unwrap()
			.key
			.encrypt_sortable(65321)
			.unwrap();

		std::println!("a: {a}, b: {b}, c: {c}");

		assert!(a < b);
		assert!(b < c);

		assert_eq!(a, 17455249);
		assert_eq!(b, 17488544);
		assert_eq!(c, 4280794268);
	}
}
