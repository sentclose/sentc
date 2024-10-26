use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{
	CreateData,
	GroupHmacData,
	GroupKeyServerOutput,
	GroupKeysForNewMemberServerInput,
	GroupSortableData,
	KeyRotationInput,
};
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_common::UserId;
use sentc_crypto_std_keys::util::{PublicKey, SecretKey, SignKey, SymKeyFormatExport, SymmetricKey};
use sentc_crypto_utils::cryptomat::KeyToString;
use serde_json::from_str;

use crate::entities::group::{GroupKeyDataExport, GroupOutDataExport, GroupOutDataKeyExport, GroupOutDataLightExport};
use crate::keys::std::StdGroup;
use crate::SdkError;

macro_rules! prepare_prepare_group_keys_for_new_member {
	($requester_public_key_data:expr,$group_keys:expr,|$uk:ident,$split_group_keys:ident|$scope:block) => {{
		let $uk = sentc_crypto_common::user::UserPublicKeyData::from_string($requester_public_key_data).map_err($crate::SdkError::JsonParseFailed)?;

		let group_keys: alloc::vec::Vec<sentc_crypto_std_keys::util::SymKeyFormatExport> =
			serde_json::from_str($group_keys).map_err($crate::SdkError::JsonParseFailed)?;

		//split group key and id
		let saved_keys = group_keys
			.iter()
			.map(|k| k.try_into())
			.collect::<Result<alloc::vec::Vec<sentc_crypto_std_keys::util::SymmetricKey>, _>>()?;

		let $split_group_keys = $crate::group::prepare_group_keys_for_new_member_with_ref(&saved_keys);

		$scope
	}};
}

pub(crate) use prepare_prepare_group_keys_for_new_member;

pub fn prepare_create_typed(creators_public_key: &str, sign_key: Option<&str>, starter: UserId) -> Result<CreateData, String>
{
	let key: PublicKey = creators_public_key.parse()?;
	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };

	Ok(StdGroup::prepare_create_typed(&key, sign_key.as_ref(), starter)?)
}

pub fn prepare_create(creators_public_key: &str, sign_key: Option<&str>, starter: UserId) -> Result<String, String>
{
	let key: PublicKey = creators_public_key.parse()?;
	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };

	Ok(StdGroup::prepare_create(&key, sign_key.as_ref(), starter)?)
}

pub fn prepare_create_batch_typed(creators_public_key: &str, sign_key: Option<&str>, starter: UserId)
	-> Result<(CreateData, String, String), String>
{
	let key: PublicKey = creators_public_key.parse()?;
	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };

	let out = StdGroup::prepare_create_batch_typed(&key, sign_key.as_ref(), starter)?;

	let public_key = out.1.to_string()?;
	let group_key = out.2.to_string()?;

	Ok((out.0, public_key, group_key))
}

pub fn prepare_create_batch(creators_public_key: &str, sign_key: Option<&str>, starter: UserId) -> Result<(String, String, String), String>
{
	let key: PublicKey = creators_public_key.parse()?;
	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };

	let out = StdGroup::prepare_create_batch(&key, sign_key.as_ref(), starter)?;

	let public_key = out.1.to_string()?;
	let group_key = out.2.to_string()?;

	Ok((out.0, public_key, group_key))
}

pub fn key_rotation(
	previous_group_key: &str,
	invoker_public_key: &str,
	user_group: bool,
	sign_key: Option<&str>,
	starter: UserId,
) -> Result<String, String>
{
	//the ids come from the storage of the current impl from the sdk, the group key id comes from get group

	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };

	let previous_group_key: SymmetricKey = previous_group_key.parse()?;
	let invoker_public_key: PublicKey = invoker_public_key.parse()?;

	Ok(StdGroup::key_rotation(
		&previous_group_key,
		&invoker_public_key,
		user_group,
		sign_key.as_ref(),
		starter,
	)?)
}

pub fn get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, String>
{
	Ok(super::group::get_done_key_rotation_server_input(server_output)?)
}

pub(crate) fn prepare_done_key_rotation(
	private_key: &str,
	public_key: &str,
	previous_group_key: &str,
) -> Result<(SecretKey, PublicKey, SymmetricKey), String>
{
	let private_key: SecretKey = private_key.parse()?;
	let public_key: PublicKey = public_key.parse()?;
	let previous_group_key: SymmetricKey = previous_group_key.parse()?;

	Ok((private_key, public_key, previous_group_key))
}

pub fn done_key_rotation(private_key: &str, public_key: &str, previous_group_key: &str, server_output: &str) -> Result<String, String>
{
	let server_output = get_done_key_rotation_server_input(server_output)?;

	let (private_key, public_key, previous_group_key) = prepare_done_key_rotation(private_key, public_key, previous_group_key)?;

	Ok(StdGroup::done_key_rotation(
		&private_key,
		&public_key,
		&previous_group_key,
		server_output,
	)?)
}

pub fn decrypt_group_hmac_key(group_key: &str, server_key_output: &str) -> Result<String, String>
{
	let server_output: GroupHmacData = from_str(server_key_output).map_err(SdkError::JsonParseFailed)?;

	let group_key: SymmetricKey = group_key.parse()?;

	let hmac_key = StdGroup::decrypt_group_hmac_key(&group_key, server_output)?;

	Ok(hmac_key.to_string()?)
}

pub fn decrypt_group_sortable_key(group_key: &str, server_key_output: &str) -> Result<String, String>
{
	let server_output: GroupSortableData = from_str(server_key_output).map_err(SdkError::JsonParseFailed)?;

	let group_key: SymmetricKey = group_key.parse()?;

	let key = StdGroup::decrypt_group_sortable_key(&group_key, server_output)?;

	Ok(key.to_string()?)
}

pub fn decrypt_group_keys(private_key: &str, server_key_output: &str, verify_key: Option<&str>) -> Result<GroupKeyDataExport, String>
{
	let verify_key = if let Some(k) = verify_key {
		Some(UserVerifyKeyData::from_string(k).map_err(SdkError::JsonParseFailed)?)
	} else {
		None
	};

	let server_key_output = GroupKeyServerOutput::from_string(server_key_output).map_err(SdkError::JsonParseFailed)?;

	let private_key: SecretKey = private_key.parse()?;

	let result = StdGroup::decrypt_group_keys(&private_key, server_key_output, verify_key.as_ref())?;

	Ok(result.try_into()?)
}

/**
Call this fn for pagination key fetch
 */
pub fn get_group_keys_from_server_output(server_output: &str) -> Result<Vec<GroupOutDataKeyExport>, SdkError>
{
	let out = super::group::get_group_keys_from_server_output(server_output)?;

	out.into_iter()
		.map(|k| k.try_into())
		.collect::<Result<_, SdkError>>()
}

pub fn get_group_key_from_server_output(server_output: &str) -> Result<GroupOutDataKeyExport, SdkError>
{
	let out = super::group::get_group_key_from_server_output(server_output)?;

	out.try_into()
}

pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLightExport, String>
{
	let out = super::group::get_group_light_data(server_output)?;

	Ok(out.into())
}

/**
Returns the Group data.

Returns the server keys to use get_group_keys to decrypt each group key with the right private key
 */
pub fn get_group_data(server_output: &str) -> Result<GroupOutDataExport, String>
{
	let out = super::group::get_group_data(server_output)?;

	Ok(out.try_into()?)
}

pub fn prepare_group_keys_for_new_member_with_group_public_key(
	requester_public_key: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, String>
{
	//the same as the other fn but with the public key format and not the exported public key from server fetch
	let group_keys: Vec<SymKeyFormatExport> = from_str(group_keys).map_err(SdkError::JsonParseFailed)?;

	//split group key and id
	let saved_keys = group_keys
		.iter()
		.map(|k| k.try_into())
		.collect::<Result<Vec<SymmetricKey>, _>>()?;

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	let requester_public_key: PublicKey = requester_public_key.parse()?;

	Ok(StdGroup::prepare_group_keys_for_new_member_with_group_public_key(
		&requester_public_key,
		&split_group_keys,
		key_session,
		rank,
	)?)
}

pub fn prepare_group_keys_for_new_member_typed(
	requester_public_key_data: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, String>
{
	prepare_prepare_group_keys_for_new_member!(
		requester_public_key_data,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::prepare_group_keys_for_new_member_typed(
				&requester_public_key,
				&split_group_keys,
				key_session,
				rank,
			)?)
		}
	)
}

pub fn prepare_group_keys_for_new_member(
	requester_public_key_data: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<String, String>
{
	prepare_prepare_group_keys_for_new_member!(
		requester_public_key_data,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::prepare_group_keys_for_new_member(
				&requester_public_key,
				&split_group_keys,
				key_session,
				rank,
			)?)
		}
	)
}

pub fn prepare_group_keys_for_new_member_via_session(requester_public_key_data: &str, group_keys: &str) -> Result<String, String>
{
	prepare_prepare_group_keys_for_new_member!(
		requester_public_key_data,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::prepare_group_keys_for_new_member_via_session(
				&requester_public_key,
				&split_group_keys,
			)?)
		}
	)
}

pub(crate) fn prepare_group_keys_for_new_member_with_ref(saved_keys: &Vec<SymmetricKey>) -> Vec<&SymmetricKey>
{
	//this is needed because we need only ref of the group key not the group key itself.
	//but for the non rust version the key is just a string which gets

	let mut split_group_keys = Vec::with_capacity(saved_keys.len());

	for saved_key in saved_keys {
		split_group_keys.push(saved_key);
	}

	split_group_keys
}

pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, String>
{
	Ok(super::group::prepare_change_rank(user_id, new_rank, admin_rank)?)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;
	use core::str::FromStr;

	use base64ct::{Base64, Encoding};
	use sentc_crypto_common::group::{
		CreateData,
		DoneKeyRotationData,
		GroupHmacData,
		GroupKeysForNewMember,
		GroupKeysForNewMemberServerInput,
		GroupServerData,
		GroupSortableData,
		GroupUserAccessBy,
		KeyRotationData,
	};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::cryptomat::Pk;
	use sentc_crypto_std_keys::util::PublicKey;
	use sentc_crypto_utils::cryptomat::PkWrapper;
	use serde_json::to_string;

	use super::*;
	use crate::group::test_fn::create_group_export;
	use crate::user::test_fn::create_user_export;

	#[test]
	fn test_create_group()
	{
		//create a rust dummy user
		let user = create_user_export();

		let group = prepare_create(
			&user.user_keys[0].public_key,
			Some(&user.user_keys.first().unwrap().sign_key),
			user.user_id,
		)
		.unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		let pk = PublicKey::from_str(&user.user_keys[0].public_key).unwrap();

		assert_eq!(group.creator_public_key_id, pk.key_id);
	}

	#[test]
	fn test_create_and_get_group()
	{
		//test here only basic functions, if function panics. the key test is done in crypto mod

		let user = create_user_export();

		let (data, _, _, _, _) = create_group_export(&user.user_keys[0]);

		assert_eq!(data.group_id, "123".to_string());
	}

	#[test]
	fn test_get_group_data_and_keys()
	{
		let user = create_user_export();

		let (_, key_data, group_server_out, _, _) = create_group_export(&user.user_keys[0]);

		let keys = group_server_out.keys;

		let single_fetch = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(&keys[0]),
		};

		let single_fetch = to_string(&single_fetch).unwrap();

		let server_key_out = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(keys),
		};

		let server_key_out = server_key_out.to_string().unwrap();

		let group_keys_from_server_out = get_group_keys_from_server_output(server_key_out.as_str()).unwrap();

		let group_keys_from_server_out = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			&group_keys_from_server_out[0].key_data,
			None,
		)
		.unwrap();

		//only one key
		assert_eq!(
			key_data[0].group_key.to_string(),
			group_keys_from_server_out.group_key
		);

		//fetch the key single
		let key = get_group_key_from_server_output(single_fetch.as_str()).unwrap();

		let group_keys_from_single_server_out = decrypt_group_keys(user.user_keys[0].private_key.as_str(), &key.key_data, None).unwrap();

		assert_eq!(
			key_data[0].group_key.to_string(),
			group_keys_from_single_server_out.group_key
		);
	}

	#[test]
	fn test_prepare_group_keys_for_new_member()
	{
		let user = create_user_export();

		let user1 = create_user_export();

		let group_create = prepare_create(
			user.user_keys[0].public_key.as_str(),
			Some(&user.user_keys[0].sign_key),
			"".to_string(),
		)
		.unwrap();
		let group_create = CreateData::from_string(group_create.as_str()).unwrap();

		let group_server_output_user_0 = GroupKeyServerOutput {
			encrypted_group_key: group_create.encrypted_group_key.to_string(),
			group_key_alg: group_create.group_key_alg.to_string(),
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key.to_string(),
			public_group_key: group_create.public_group_key.to_string(),
			keypair_encrypt_alg: group_create.keypair_encrypt_alg.to_string(),
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			signed_by_user_id: group_create.signed_by_user_id.clone(),
			signed_by_user_sign_key_id: group_create.signed_by_user_sign_key_id.clone(),
			group_key_sig: group_create.group_key_sig.clone(),
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_0 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_0],
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
				encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let group_key_user_0 = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			group_data_user_0.keys[0].key_data.as_str(),
			None,
		)
		.unwrap();

		let g_k: SymKeyFormatExport = from_str(&group_key_user_0.group_key).unwrap();

		let group_keys = to_string(&vec![g_k]).unwrap();

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member(
			user1.user_keys[0].exported_public_key.as_str(),
			group_keys.as_str(),
			false,
			None,
		)
		.unwrap();
		let out = GroupKeysForNewMemberServerInput::from_string(out.as_str()).unwrap();
		let out_group_1 = &out.keys[0]; //this group only got one key

		let group_server_output_user_1 = GroupKeyServerOutput {
			encrypted_group_key: out_group_1.encrypted_group_key.to_string(),
			group_key_alg: out_group_1.alg.to_string(),
			group_key_id: out_group_1.key_id.to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key,
			public_group_key: group_create.public_group_key,
			keypair_encrypt_alg: group_create.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			signed_by_user_id: group_create.signed_by_user_id.clone(),
			signed_by_user_sign_key_id: group_create.signed_by_user_sign_key_id.clone(),
			group_key_sig: group_create.group_key_sig.clone(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_1 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_1],
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key,
				encrypted_hmac_alg: group_create.encrypted_hmac_alg,
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
				encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();
		let group_key_user_1 = decrypt_group_keys(
			user1.user_keys[0].private_key.as_str(),
			group_data_user_1.keys[0].key_data.as_str(),
			Some(&user.user_keys[0].exported_verify_key),
		)
		.unwrap();

		let group_key_0 = SymmetricKey::from_str(&group_key_user_0.group_key).unwrap();
		let group_key_1 = SymmetricKey::from_str(&group_key_user_1.group_key).unwrap();

		assert_eq!(group_key_0.key_id, group_key_1.key_id);

		assert_eq!(&group_key_0.key.as_ref(), &group_key_1.key.as_ref());
	}

	#[test]
	fn test_prepare_group_keys_for_new_member_via_session()
	{
		let user = create_user_export();
		let user_keys = &user.user_keys[0];

		let user1 = create_user_export();
		let user_keys1 = &user1.user_keys[0];

		let group_create = prepare_create(user_keys.public_key.as_str(), None, "".to_string()).unwrap();
		let group_create = CreateData::from_string(group_create.as_str()).unwrap();

		let group_server_output_user_0 = GroupKeyServerOutput {
			encrypted_group_key: group_create.encrypted_group_key.to_string(),
			group_key_alg: group_create.group_key_alg.to_string(),
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key.to_string(),
			public_group_key: group_create.public_group_key.to_string(),
			keypair_encrypt_alg: group_create.keypair_encrypt_alg.to_string(),
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			group_key_sig: None,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_0 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_0],
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
				encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let group_key_user_0 = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			group_data_user_0.keys[0].key_data.as_str(),
			None,
		)
		.unwrap();

		let g_k: SymKeyFormatExport = from_str(&group_key_user_0.group_key).unwrap();
		let group_keys = to_string(&vec![g_k]).unwrap();

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member_via_session(user_keys1.exported_public_key.as_str(), group_keys.as_str()).unwrap();

		let out: Vec<GroupKeysForNewMember> = from_str(out.as_str()).unwrap();
		let out_group_1 = &out[0]; //this group only got one key

		let group_server_output_user_1 = GroupKeyServerOutput {
			encrypted_group_key: out_group_1.encrypted_group_key.to_string(),
			group_key_alg: out_group_1.alg.to_string(),
			group_key_id: out_group_1.key_id.to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key,
			public_group_key: group_create.public_group_key,
			keypair_encrypt_alg: group_create.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			group_key_sig: None,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_1 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_1],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key,
				encrypted_hmac_alg: group_create.encrypted_hmac_alg,
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
				encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();
		let group_key_user_1 = decrypt_group_keys(
			user_keys1.private_key.as_str(),
			group_data_user_1.keys[0].key_data.as_str(),
			None,
		)
		.unwrap();

		let group_key_0 = SymmetricKey::from_str(&group_key_user_0.group_key).unwrap();
		let group_key_1 = SymmetricKey::from_str(&group_key_user_1.group_key).unwrap();

		assert_eq!(group_key_0.key_id, group_key_1.key_id);

		assert_eq!(&group_key_0.key.as_ref(), &group_key_1.key.as_ref());
	}

	#[test]
	fn test_key_rotation()
	{
		let user = create_user_export();
		let user_keys = &user.user_keys[0];

		let (_data, key_data, group_server_out, _, _) = create_group_export(user_keys);

		let rotation_out = key_rotation(
			key_data[0].group_key.as_str(),
			user_keys.public_key.as_str(),
			false,
			None,
			"".to_string(),
		)
		.unwrap();
		let rotation_out = KeyRotationData::from_string(rotation_out.as_str()).unwrap();

		//get the new group key directly because for the invoker the key is already encrypted by the own public key
		let server_key_output_direct = GroupKeyServerOutput {
			encrypted_group_key: rotation_out.encrypted_group_key_by_user.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: "abc".to_string(),
			time: 0,
			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			group_key_sig: None,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output_direct.to_string().unwrap(),
			None,
		)
		.unwrap();

		//simulate server key rotation encrypt. encrypt the ephemeral_key (encrypted by the previous room key) with the public keys of all users
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let pk = PublicKey::from_str(&user_keys.public_key).unwrap();

		let encrypted_ephemeral_key_by_group_key_and_public_key = pk.get_key().encrypt(&encrypted_ephemeral_key).unwrap();

		let server_output = KeyRotationInput {
			error: None,
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),
		};

		let done_key_rotation = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
		)
		.unwrap();
		let done_key_rotation = DoneKeyRotationData::from_string(done_key_rotation.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg,
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation.public_key_id,
			time: 0,
			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			group_key_sig: None,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
			None,
		)
		.unwrap();

		let old_group_key = SymmetricKey::from_str(&key_data[0].group_key).unwrap();

		let new_group_key_direct = SymmetricKey::from_str(&new_group_key_direct.group_key).unwrap();

		let new_group_key = SymmetricKey::from_str(&out.group_key).unwrap();

		//the new group key must be different after key rotation
		assert_ne!(old_group_key.key.as_ref(), new_group_key.key.as_ref());
		//should be the same for all users
		assert_eq!(new_group_key_direct.key.as_ref(), new_group_key.key.as_ref());
	}

	#[test]
	fn test_signed_key_rotation()
	{
		let user = create_user_export();
		let user_keys = &user.user_keys[0];

		let (_data, key_data, group_server_out, _, _) = create_group_export(user_keys);

		let rotation_out = key_rotation(
			key_data[0].group_key.as_str(),
			user_keys.public_key.as_str(),
			false,
			Some(&user_keys.sign_key),
			user.user_id.clone(),
		)
		.unwrap();
		let rotation_out = KeyRotationData::from_string(rotation_out.as_str()).unwrap();

		assert_eq!(rotation_out.signed_by_user_id.as_ref(), Some(&user.user_id));
		assert_eq!(
			rotation_out.signed_by_user_sign_key_id.as_ref(),
			Some(&user_keys.group_key_id)
		);

		//__________________________________________________________________________________________
		//get the new group key directly because for the invoker the key is already encrypted by the own public key
		let server_key_output_direct = GroupKeyServerOutput {
			encrypted_group_key: rotation_out.encrypted_group_key_by_user.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: "abc".to_string(),
			signed_by_user_id: rotation_out.signed_by_user_id.clone(),
			signed_by_user_sign_key_id: rotation_out.signed_by_user_sign_key_id.clone(),
			group_key_sig: rotation_out.group_key_sig.clone(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output_direct.to_string().unwrap(),
			Some(&user.user_keys[0].exported_verify_key),
		)
		.unwrap();

		//__________________________________________________________________________________________
		//do the server part
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let pk = PublicKey::from_str(&user_keys.public_key).unwrap();

		let encrypted_ephemeral_key_by_group_key_and_public_key = pk.get_key().encrypt(&encrypted_ephemeral_key).unwrap();

		let server_output = KeyRotationInput {
			error: None,
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),
		};

		//__________________________________________________________________________________________
		//test done key rotation without verify key (should work even if it is signed, sign is here ignored)

		let done_key_rotation_out = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
		)
		.unwrap();
		let done_key_rotation_out = DoneKeyRotationData::from_string(done_key_rotation_out.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation_out.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation_out.public_key_id,
			time: 0,
			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			group_key_sig: None,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
			None,
		)
		.unwrap();

		let old_group_key = SymmetricKey::from_str(&key_data[0].group_key).unwrap();

		let new_group_key_direct = SymmetricKey::from_str(&new_group_key_direct.group_key).unwrap();

		let new_group_key = SymmetricKey::from_str(&out.group_key).unwrap();

		//the new group key must be different after key rotation
		assert_ne!(old_group_key.key.as_ref(), new_group_key.key.as_ref());
		//should be the same for all users
		assert_eq!(new_group_key_direct.key.as_ref(), new_group_key.key.as_ref());

		//__________________________________________________________________________________________
		//now test rotation with verify

		let done_key_rotation_out = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
		)
		.unwrap();
		let done_key_rotation_out = DoneKeyRotationData::from_string(done_key_rotation_out.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation_out.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg,
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation_out.public_key_id,
			signed_by_user_id: rotation_out.signed_by_user_id.clone(),
			signed_by_user_sign_key_id: rotation_out.signed_by_user_sign_key_id.clone(),
			group_key_sig: rotation_out.group_key_sig.clone(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
			Some(&user_keys.exported_verify_key),
		)
		.unwrap();

		let old_group_key = SymmetricKey::from_str(&key_data[0].group_key).unwrap();

		let new_group_key = SymmetricKey::from_str(&out.group_key).unwrap();

		//the new group key must be different after key rotation
		assert_ne!(old_group_key.key.as_ref(), new_group_key.key.as_ref());
		//should be the same for all users
		assert_eq!(new_group_key_direct.key.as_ref(), new_group_key.key.as_ref());
	}
}
