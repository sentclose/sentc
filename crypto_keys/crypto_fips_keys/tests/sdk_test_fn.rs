#![allow(unused)]

use sentc_crypto::entities::group::{GroupKeyData, GroupOutData};
use sentc_crypto::group::group::get_group_data;
use sentc_crypto::util;
use sentc_crypto::util::server::generate_salt_from_base64_to_string;
use sentc_crypto_common::group::{CreateData, GroupHmacData, GroupKeyServerOutput, GroupServerData, GroupSortableData, GroupUserAccessBy};
use sentc_crypto_common::user::{
	DoneLoginServerKeysOutput,
	DoneLoginServerOutput,
	KeyDerivedData,
	PrepareLoginSaltServerOutput,
	RegisterData,
	VerifyLoginInput,
	VerifyLoginOutput,
};
use sentc_crypto_common::ServerOutput;
use sentc_crypto_fips_keys::core::pw_hash::ClientRandomValue;
use sentc_crypto_fips_keys::sdk::{FipsGroup, FipsUser, FipsUserDataInt, FipsUserKeyDataInt};
use sentc_crypto_fips_keys::util::{HmacKey, PublicKey, SecretKey, SortableKey, SymmetricKey};

pub fn simulate_server_prepare_login(derived: &KeyDerivedData) -> String
{
	//and now try to log in
	//normally the salt gets calc by the api
	let salt_string =
		generate_salt_from_base64_to_string::<ClientRandomValue>(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "").unwrap();

	ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(PrepareLoginSaltServerOutput {
			salt_string,
			derived_encryption_key_alg: derived.derived_alg.clone(),
		}),
	}
	.to_string()
	.unwrap()
}

pub fn simulate_server_done_login(data: RegisterData) -> DoneLoginServerOutput
{
	let RegisterData {
		device, ..
	} = data;

	let challenge = util::server::encrypt_login_verify_challenge::<SecretKey>(
		&device.derived.public_key,
		&device.derived.keypair_encrypt_alg,
		"abcd",
	)
	.unwrap();

	//get the server output back
	let device_keys = DoneLoginServerKeysOutput {
		encrypted_master_key: device.master_key.encrypted_master_key,
		encrypted_private_key: device.derived.encrypted_private_key,
		encrypted_sign_key: device.derived.encrypted_sign_key,
		public_key_string: device.derived.public_key,
		verify_key_string: device.derived.verify_key,
		keypair_encrypt_alg: device.derived.keypair_encrypt_alg,
		keypair_sign_alg: device.derived.keypair_sign_alg,
		keypair_encrypt_id: "abc".to_string(),
		keypair_sign_id: "dfg".to_string(),
		user_id: "abc".to_string(),
		device_id: "abc".to_string(),
		user_group_id: "abc".to_string(),
	};

	DoneLoginServerOutput {
		device_keys,
		challenge,
	}
}

pub fn simulate_verify_login(data: RegisterData, challenge: &str) -> String
{
	let challenge: VerifyLoginInput = serde_json::from_str(challenge).unwrap();
	assert_eq!(challenge.challenge, "abcd");

	let RegisterData {
		group, ..
	} = data;

	let user_keys = vec![GroupKeyServerOutput {
		encrypted_group_key: group.encrypted_group_key,
		group_key_alg: group.group_key_alg,
		group_key_id: "abc".to_string(),
		encrypted_private_group_key: group.encrypted_private_group_key,
		public_group_key: group.public_group_key,
		keypair_encrypt_alg: group.keypair_encrypt_alg,
		key_pair_id: "".to_string(),
		user_public_key_id: "abc".to_string(),
		time: 0,
		encrypted_sign_key: group.encrypted_sign_key,
		verify_key: group.verify_key,
		keypair_sign_alg: group.keypair_sign_alg,
		keypair_sign_id: Some("abc".to_string()),
		public_key_sig: group.public_key_sig,
		public_key_sig_key_id: Some("abc".to_string()),
	}];

	let hmac_keys = vec![GroupHmacData {
		id: "123".to_string(),
		encrypted_hmac_encryption_key_id: "".to_string(),
		encrypted_hmac_key: group.encrypted_hmac_key,
		encrypted_hmac_alg: group.encrypted_hmac_alg,
		time: 0,
	}];

	let out = VerifyLoginOutput {
		user_keys,
		hmac_keys,
		jwt: "abc".to_string(),
		refresh_token: "abc".to_string(),
	};

	ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(out),
	}
	.to_string()
	.unwrap()
}

pub fn create_user() -> FipsUserDataInt
{
	let username = "admin";
	let password = "12345";

	let out_string = FipsUser::register(username, password).unwrap();

	let out = RegisterData::from_string(out_string.as_str()).unwrap();
	let server_output = simulate_server_prepare_login(&out.device.derived);

	let (_input, auth_key, master_key_encryption_key) = FipsUser::prepare_login(username, password, &server_output).unwrap();

	let server_output = simulate_server_done_login(out);

	let done_login = FipsUser::done_login(
		&master_key_encryption_key,
		auth_key,
		username.to_string(),
		server_output,
	)
	.unwrap();

	let server_output = simulate_verify_login(RegisterData::from_string(&out_string).unwrap(), &done_login.challenge);

	FipsUser::verify_login(
		&server_output,
		done_login.user_id,
		done_login.device_id,
		done_login.device_keys,
	)
	.unwrap()
}

pub fn create_group(
	user: &FipsUserKeyDataInt,
) -> (
	GroupOutData,
	Vec<GroupKeyData<SymmetricKey, SecretKey, PublicKey>>,
	GroupServerData,
	Vec<HmacKey>,
	Vec<SortableKey>,
)
{
	let group = FipsGroup::prepare_create(&user.public_key).unwrap();
	let group = CreateData::from_string(group.as_str()).unwrap();

	let group_server_output = GroupKeyServerOutput {
		encrypted_group_key: group.encrypted_group_key,
		group_key_alg: group.group_key_alg,
		group_key_id: "123".to_string(),
		encrypted_private_group_key: group.encrypted_private_group_key,
		public_group_key: group.public_group_key,
		keypair_encrypt_alg: group.keypair_encrypt_alg,
		key_pair_id: "123".to_string(),
		user_public_key_id: "123".to_string(),
		time: 0,
		encrypted_sign_key: None,
		verify_key: None,
		keypair_sign_alg: None,
		keypair_sign_id: None,
		public_key_sig: None,
		public_key_sig_key_id: None,
	};

	let group_server_output = GroupServerData {
		group_id: "123".to_string(),
		parent_group_id: None,
		keys: vec![group_server_output],
		hmac_keys: vec![GroupHmacData {
			id: "123".to_string(),
			encrypted_hmac_encryption_key_id: "".to_string(),
			encrypted_hmac_key: group.encrypted_hmac_key,
			encrypted_hmac_alg: group.encrypted_hmac_alg,
			time: 0,
		}],
		sortable_keys: vec![GroupSortableData {
			id: "123".to_string(),
			encrypted_sortable_key: group.encrypted_sortable_key,
			encrypted_sortable_alg: group.encrypted_sortable_alg,
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

	//to avoid the clone trait on the real type
	let group_ser_str = group_server_output.to_string().unwrap();

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(group_server_output),
	};

	let out = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

	let group_keys: Vec<_> = out
		.keys
		.into_iter()
		.map(|k| FipsGroup::decrypt_group_keys(&user.private_key, k).unwrap())
		.collect();

	let hmac_keys = out
		.hmac_keys
		.into_iter()
		.map(|k| FipsGroup::decrypt_group_hmac_key(&group_keys[0].group_key, k).unwrap())
		.collect();

	let sortable_keys = out
		.sortable_keys
		.into_iter()
		.map(|k| FipsGroup::decrypt_group_sortable_key(&group_keys[0].group_key, k).unwrap())
		.collect();

	(
		GroupOutData {
			keys: vec![],
			hmac_keys: vec![],
			sortable_keys: vec![],
			parent_group_id: out.parent_group_id,
			key_update: out.key_update,
			created_time: out.created_time,
			joined_time: out.joined_time,
			rank: out.rank,
			group_id: out.group_id,
			access_by_group_as_member: out.access_by_group_as_member,
			access_by_parent_group: out.access_by_parent_group,
			is_connected_group: out.is_connected_group,
		},
		group_keys,
		GroupServerData::from_string(group_ser_str.as_str()).unwrap(),
		hmac_keys,
		sortable_keys,
	)
}
