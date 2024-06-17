use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::content_searchable::SearchableCreateOutput;
use sentc_crypto_std_keys::util::HmacKey;
use sentc_crypto_utils::cryptomat::SearchableKeyWrapper;

pub fn create_searchable_raw(key: &str, data: &str, full: bool, limit: Option<usize>) -> Result<Vec<String>, String>
{
	let key: HmacKey = key.parse()?;

	Ok(key.create_searchable_raw(data, full, limit)?)
}

pub fn create_searchable(key: &str, data: &str, full: bool, limit: Option<usize>) -> Result<SearchableCreateOutput, String>
{
	let key: HmacKey = key.parse()?;

	Ok(key.create_searchable(data, full, limit)?)
}

pub fn search(key: &str, data: &str) -> Result<String, String>
{
	let key: HmacKey = key.parse()?;

	Ok(key.search(data)?)
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::group::test_fn::create_group_export;
	use crate::user::test_fn::create_user_export;

	#[test]
	fn test_create_full_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user_export();
		let (_, _, _, hmac_keys, _) = create_group_export(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, text, true, None).unwrap();

		//should be only one -> the full hash
		assert_eq!(string.hashes.len(), 1);
	}

	#[test]
	fn test_create_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user_export();
		let (_, _, _, hmac_keys, _) = create_group_export(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, text, false, None).unwrap();

		assert_eq!(string.hashes.len(), 39);
	}

	#[test]
	fn test_searchable_full_item()
	{
		//create a group and use the hmac key
		let user = create_user_export();
		let (_, _, _, hmac_keys, _) = create_group_export(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = create_searchable(hmac_key, text, true, None).unwrap();

		assert_eq!(out.hashes.len(), 1);

		//now get the output of the prepare search
		let search_str = search(hmac_key, "123").unwrap();

		//should not contain only a part of the word because we used full
		assert!(!out.hashes.contains(&search_str));

		//but should contain the full word
		let search_str = search(hmac_key, "123*+^êéèüöß@€&$ 👍 🚀 😎").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user_export();
		let (_, _, _, hmac_keys, _) = create_group_export(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = create_searchable(hmac_key, text, false, None).unwrap();

		assert_eq!(out.hashes.len(), 39);

		//now get the output of the prepare search
		let search_str = search(hmac_key, "123").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_not_create_same_output_with_different_hmac_keys()
	{
		let user = create_user_export();
		let (_, _, _, hmac_keys, _) = create_group_export(&user.user_keys[0]);
		let hmac_key = &hmac_keys[0];

		let (_, _, _, hmac_keys2, _) = create_group_export(&user.user_keys[0]);
		let hmac_key2 = &hmac_keys2[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let out = create_searchable(hmac_key, text, false, None).unwrap();

		let search_str = search(hmac_key, "123").unwrap();

		let search_str2 = search(hmac_key2, "123").unwrap();

		assert_ne!(search_str, search_str2);

		assert!(out.hashes.contains(&search_str));

		assert!(!out.hashes.contains(&search_str2));
	}
}
