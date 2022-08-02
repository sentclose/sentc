use alloc::format;
use alloc::string::{String, ToString};
#[cfg(not(feature = "rust"))]
use alloc::vec;

#[cfg(not(feature = "rust"))]
use sentc_crypto_common::group::{CreateData, GroupKeyServerOutput, GroupServerData};
use sentc_crypto_common::user::{DoneLoginServerKeysOutput, PrepareLoginSaltServerOutput, RegisterData};
use sentc_crypto_common::ServerOutput;
#[cfg(feature = "rust")]
use sentc_crypto_core::Sk;

use crate::user::{done_login, prepare_login, register};
use crate::util_server::generate_salt_from_base64_to_string;
#[cfg(not(feature = "rust"))]
use crate::PrivateKeyFormat;

#[cfg(feature = "rust")]
pub fn register_test_full() -> String
{
	let username = "admin";
	let password = "abc*èéöäüê";

	#[cfg(feature = "rust")]
	let out = register(username, password).unwrap();

	let out = RegisterData::from_string(out.as_str()).unwrap();
	let RegisterData {
		derived,
		master_key,
		..
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let salt_from_rand_value = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "").unwrap();

	let server_output = PrepareLoginSaltServerOutput {
		salt_string: salt_from_rand_value,
		derived_encryption_key_alg: derived.derived_alg.clone(),
	};

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(server_output),
	};

	//back to the client, send prep login out string to the server if it is no err
	#[cfg(feature = "rust")]
	let (_, master_key_encryption_key) = prepare_login(username, password, server_output.to_string().unwrap().as_str()).unwrap();

	//get the server output back
	let server_output = DoneLoginServerKeysOutput {
		encrypted_master_key: master_key.encrypted_master_key,
		encrypted_private_key: derived.encrypted_private_key,
		encrypted_sign_key: derived.encrypted_sign_key,
		public_key_string: derived.public_key,
		verify_key_string: derived.verify_key,
		keypair_encrypt_alg: derived.keypair_encrypt_alg,
		keypair_sign_alg: derived.keypair_sign_alg,
		keypair_encrypt_id: "abc".to_string(),
		keypair_sign_id: "dfg".to_string(),
		jwt: "jwt".to_string(),
		user_id: "abc".to_string(),
	};

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(server_output),
	};

	//now save the values
	#[cfg(feature = "rust")]
	let login_out = done_login(
		&master_key_encryption_key,
		server_output.to_string().unwrap().as_str(),
	)
	.unwrap();

	let private_key = match login_out.private_key.key {
		Sk::Ecies(k) => k,
	};

	format!("register done with private key: {:?}", private_key)
}

#[cfg(not(feature = "rust"))]
pub fn register_test_full() -> String
{
	let username = "admin";
	let password = "abc*èéöäüê";

	#[cfg(not(feature = "rust"))]
	let out = register(username, password).unwrap();

	let out = RegisterData::from_string(out.as_str()).unwrap();
	let RegisterData {
		derived,
		master_key,
		..
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let salt_from_rand_value = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "").unwrap();

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(PrepareLoginSaltServerOutput {
			salt_string: salt_from_rand_value,
			derived_encryption_key_alg: derived.derived_alg.clone(),
		}),
	};

	//back to the client, send prep login out string to the server if it is no err
	#[cfg(not(feature = "rust"))]
	let (_auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.to_string().unwrap().as_str()).unwrap();

	//get the server output back
	let server_output = DoneLoginServerKeysOutput {
		encrypted_master_key: master_key.encrypted_master_key,
		encrypted_private_key: derived.encrypted_private_key,
		encrypted_sign_key: derived.encrypted_sign_key,
		public_key_string: derived.public_key,
		verify_key_string: derived.verify_key,
		keypair_encrypt_alg: derived.keypair_encrypt_alg,
		keypair_sign_alg: derived.keypair_sign_alg,
		keypair_encrypt_id: "abc".to_string(),
		keypair_sign_id: "dfg".to_string(),
		jwt: "jwt".to_string(),
		user_id: "abc".to_string(),
	};

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(server_output),
	};

	//now save the values
	#[cfg(not(feature = "rust"))]
	let login_out = done_login(
		master_key_encryption_key.as_str(), //the value comes from prepare login
		server_output.to_string().unwrap().as_str(),
	)
	.unwrap();

	let private_key = match PrivateKeyFormat::from_string(login_out.private_key.as_str()).unwrap() {
		PrivateKeyFormat::Ecies {
			key_id: _key_id,
			key,
		} => key,
	};

	format!("register done with private key: {:?}", private_key)
}

#[cfg(not(feature = "rust"))]
pub fn simulate_server_prepare_login(register_data: &str) -> String
{
	let RegisterData {
		derived, ..
	} = RegisterData::from_string(register_data).unwrap();

	//and now try to login
	//normally the salt gets calc by the api
	let salt_string = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "").unwrap();

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(PrepareLoginSaltServerOutput {
			salt_string,
			derived_encryption_key_alg: derived.derived_alg.clone(),
		}),
	};

	server_output.to_string().unwrap()
}

#[cfg(not(feature = "rust"))]
pub fn simulate_server_done_login(register_data: &str) -> String
{
	let RegisterData {
		derived,
		master_key,
		..
	} = RegisterData::from_string(register_data).unwrap();

	let done_login_server_out = DoneLoginServerKeysOutput {
		encrypted_master_key: master_key.encrypted_master_key,
		encrypted_private_key: derived.encrypted_private_key,
		encrypted_sign_key: derived.encrypted_sign_key,
		public_key_string: derived.public_key,
		verify_key_string: derived.verify_key,
		keypair_encrypt_alg: derived.keypair_encrypt_alg,
		keypair_sign_alg: derived.keypair_sign_alg,
		keypair_encrypt_id: "abc".to_string(),
		keypair_sign_id: "dfg".to_string(),
		jwt: "jwt".to_string(),
		user_id: "abc".to_string(),
	};

	ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(done_login_server_out),
	}
	.to_string()
	.unwrap()
}

#[cfg(not(feature = "rust"))]
pub fn simulate_server_create_group(group_create_data: &str) -> String
{
	let group_create_data = CreateData::from_string(group_create_data).unwrap();

	let group_server_output = GroupKeyServerOutput {
		encrypted_group_key: group_create_data.encrypted_group_key,
		group_key_alg: group_create_data.group_key_alg,
		group_key_id: "123".to_string(),
		encrypted_private_group_key: group_create_data.encrypted_private_group_key,
		public_group_key: group_create_data.public_group_key,
		keypair_encrypt_alg: group_create_data.keypair_encrypt_alg,
		key_pair_id: "123".to_string(),
		user_public_key_id: "123".to_string(),
		time: 0,
	};

	let group_server_output = GroupServerData {
		group_id: "123".to_string(),
		parent_group_id: None,
		keys: vec![group_server_output],
		key_update: false,
		rank: 0,
		created_time: 0,
		joined_time: 0,
	};

	let server_output = ServerOutput {
		status: true,
		err_msg: None,
		err_code: None,
		result: Some(group_server_output),
	};

	server_output.to_string().unwrap()
}

#[cfg(test)]
mod test
{
	use super::*;
	#[cfg(not(feature = "rust"))]
	use crate::group::{get_group_data, prepare_create};
	#[cfg(not(feature = "rust"))]
	use crate::user::test_fn::create_user;

	#[test]
	fn test_register_test()
	{
		register_test_full();
	}

	#[cfg(not(feature = "rust"))]
	#[test]
	fn test_register_fn()
	{
		let username = "admin";
		let password = "12345";

		let out_string = register(username, password).unwrap();

		let prep_login_in = simulate_server_prepare_login(out_string.as_str());
		let (_auth_key, master_key_encryption_key) = prepare_login(username, password, prep_login_in.as_str()).unwrap();

		let server_output = simulate_server_done_login(out_string.as_str());

		let _done_login = done_login(master_key_encryption_key.as_str(), server_output.as_str()).unwrap();
	}

	#[cfg(not(feature = "rust"))]
	#[test]
	fn test_group_server()
	{
		let user = create_user();

		let group = prepare_create(user.public_key.as_str()).unwrap();

		let server_out = simulate_server_create_group(group.as_str());

		let _group_out = get_group_data(user.private_key.as_str(), server_out.as_str()).unwrap();
	}
}
