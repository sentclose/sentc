use alloc::string::String;

use sentc_crypto_common::content_searchable::{SearchCreateData, SearchCreateDataLight};

use crate::crypto_searchable::{
	create_searchable_internally,
	prepare_create_searchable_internally,
	prepare_create_searchable_light_internally,
	search_internally,
};
use crate::util::import_hmac_key;

pub fn create_searchable(key: &str, item_ref: &str, category: &str, data: &str, full: bool, limit: Option<usize>) -> Result<String, String>
{
	let key = import_hmac_key(key)?;

	let category = if category.is_empty() { None } else { Some(category) };

	Ok(create_searchable_internally(
		&key, item_ref, category, data, full, limit,
	)?)
}

pub fn prepare_create_searchable(
	key: &str,
	item_ref: &str,
	category: &str,
	data: &str,
	full: bool,
	limit: Option<usize>,
) -> Result<SearchCreateData, String>
{
	let key = import_hmac_key(key)?;

	let category = if category.is_empty() { None } else { Some(category) };

	let out = prepare_create_searchable_internally(&key, item_ref, category, data, full, limit)?;

	Ok(out)
}

pub fn prepare_create_searchable_light(key: &str, data: &str, full: bool, limit: Option<usize>) -> Result<SearchCreateDataLight, String>
{
	let key = import_hmac_key(key)?;

	let out = prepare_create_searchable_light_internally(&key, data, full, limit)?;

	Ok(out)
}

pub fn search(key: &str, data: &str) -> Result<String, String>
{
	let key = import_hmac_key(key)?;

	Ok(search_internally(&key, data)?)
}

#[cfg(test)]
mod test
{
	use sentc_crypto_common::content_searchable::SearchCreateData;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_create_full_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, "bla", "", text, true, None).unwrap();

		let out: SearchCreateData = serde_json::from_str(&string).unwrap();

		//should be only one -> the full hash
		assert_eq!(out.hashes.len(), 1);
	}

	#[test]
	fn test_create_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, "bla", "", text, false, None).unwrap();

		let out: SearchCreateData = serde_json::from_str(&string).unwrap();

		assert_eq!(out.hashes.len(), 39);
	}

	#[test]
	fn test_searchable_full_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, "bla", "", text, true, None).unwrap();

		let out: SearchCreateData = serde_json::from_str(&string).unwrap();

		assert_eq!(out.hashes.len(), 1);

		//now get the output of the prepare search
		let search_str = search(hmac_key, "123").unwrap();

		//should not contains only a part of the word because we used full
		assert!(!out.hashes.contains(&search_str));

		//but should contains the full word
		let search_str = search(hmac_key, "123*+^êéèüöß@€&$ 👍 🚀 😎").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_searchable_item()
	{
		//create a group and use the hmac key
		let user = create_user();
		let (_, _, _, hmac_keys) = create_group(&user.user_keys[0]);

		let hmac_key = &hmac_keys[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, "bla", "", text, false, None).unwrap();

		let out: SearchCreateData = serde_json::from_str(&string).unwrap();

		assert_eq!(out.hashes.len(), 39);

		//now get the output of the prepare search
		let search_str = search(hmac_key, "123").unwrap();

		assert!(out.hashes.contains(&search_str));
	}

	#[test]
	fn test_not_create_same_output_with_different_hmac_keys()
	{
		let user = create_user();
		let (_, _, _, hmac_keys) = create_group(&user.user_keys[0]);
		let hmac_key = &hmac_keys[0];

		let (_, _, _, hmac_keys2) = create_group(&user.user_keys[0]);
		let hmac_key2 = &hmac_keys2[0];

		let text = "123*+^êéèüöß@€&$ 👍 🚀 😎";

		let string = create_searchable(hmac_key, "bla", "", text, false, None).unwrap();

		let out: SearchCreateData = serde_json::from_str(&string).unwrap();

		let search_str = search(hmac_key, "123").unwrap();

		let search_str2 = search(hmac_key2, "123").unwrap();

		assert_ne!(search_str, search_str2);

		assert!(out.hashes.contains(&search_str));

		assert!(!out.hashes.contains(&search_str2));
	}
}
