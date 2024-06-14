#[cfg(not(feature = "rust"))]
mod crypto_searchable_export;

#[cfg(not(feature = "rust"))]
pub use self::crypto_searchable_export::*;

#[cfg(test)]
mod test
{
	use sentc_crypto_utils::cryptomat::SearchableKeyWrapper;

	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_create_full_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys, _) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = hmac_key.create_searchable(text, true, None).unwrap();

		//should be only one -> the full hash
		assert_eq!(out.hashes.len(), 1);
	}

	#[test]
	fn test_create_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys, _) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = hmac_key.create_searchable(text, false, None).unwrap();

		assert_eq!(out.hashes.len(), 39);
	}

	#[test]
	fn test_searchable_full_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys, _) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = hmac_key.create_searchable(text, true, None).unwrap();

		assert_eq!(out.hashes.len(), 1);

		//now get the output of the prepare search
		let search_str = hmac_key.search("123").unwrap();

		//should not contain only a part of the word because we used full
		assert!(!out.hashes.contains(&search_str));

		//but should contain the full word
		let search_str = hmac_key.search("123*+^êéèüöß@€&$ 👍 🚀 😎").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys, _) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = hmac_key.create_searchable(text, false, None).unwrap();

		assert_eq!(out.hashes.len(), 39);

		//now get the output of the prepare search
		let search_str = hmac_key.search("123").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_not_create_same_output_with_different_hmac_keys()
	{
		let user = create_user();
		let (_, _, _, hmac_keys, _) = create_group(&user.user_keys[0]);
		let hmac_key = &hmac_keys[0];

		let (_, _, _, hmac_keys2, _) = create_group(&user.user_keys[0]);
		let hmac_key2 = &hmac_keys2[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = hmac_key.create_searchable(text, false, None).unwrap();

		let search_str = hmac_key.search("123").unwrap();

		let search_str2 = hmac_key2.search("123").unwrap();

		assert_ne!(search_str, search_str2);

		assert!(out.hashes.contains(&search_str));

		assert!(!out.hashes.contains(&search_str2));
	}
}
