#![no_std]

extern crate alloc;

pub mod crypto;
mod error;
pub mod group;
pub mod user;
mod util;

use alloc::format;
use alloc::string::{String, ToString};

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::user::{DoneLoginServerKeysOutput, PrepareLoginSaltServerOutput, RegisterData};
#[cfg(feature = "rust")]
use sendclose_crypto_core::Sk;

pub use self::error::err_to_msg;
pub use self::util::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, VerifyKeyFormat};
#[cfg(not(feature = "rust"))]
use crate::user::PrepareLoginData;
use crate::user::{done_login, prepare_login, register};
use crate::util::client_random_value_from_string;

#[cfg(feature = "rust")]
pub fn register_test() -> String
{
	let password = "abc*èéöäüê";

	#[cfg(feature = "rust")]
	let out = register(password).unwrap();

	let out = RegisterData::from_string(out.as_bytes()).unwrap();
	let RegisterData {
		derived,
		master_key,
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();

	let salt_from_rand_value = sendclose_crypto_core::generate_salt(client_random_value);
	let salt_from_rand_value = Base64::encode_string(&salt_from_rand_value);

	let server_output = PrepareLoginSaltServerOutput {
		salt_string: salt_from_rand_value,
		derived_encryption_key_alg: derived.derived_alg.clone(),
		key_id: "1234".to_string(),
	};

	//back to the client, send prep login out string to the server if it is no err
	#[cfg(feature = "rust")]
	let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

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
	};

	//now save the values
	#[cfg(feature = "rust")]
	let login_out = done_login(&master_key_encryption_key, &server_output).unwrap();

	let private_key = match login_out.private_key.key {
		Sk::Ecies(k) => k,
	};

	format!("register done with private key: {:?}", private_key)
}

#[cfg(not(feature = "rust"))]
pub fn register_test() -> String
{
	let password = "abc*èéöäüê";

	#[cfg(not(feature = "rust"))]
	let out = register(password);

	let out = RegisterData::from_string(out.as_bytes()).unwrap();
	let RegisterData {
		derived,
		master_key,
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();

	let salt_from_rand_value = sendclose_crypto_core::generate_salt(client_random_value);
	let salt_from_rand_value = Base64::encode_string(&salt_from_rand_value);

	let server_output = PrepareLoginSaltServerOutput {
		salt_string: salt_from_rand_value,
		derived_encryption_key_alg: derived.derived_alg.clone(),
		key_id: "1234".to_string(),
	};

	//back to the client, send prep login out string to the server if it is no err
	#[cfg(not(feature = "rust"))]
	let prep_login_out = prepare_login(password, server_output.to_string().unwrap().as_str());

	//and get the master_key_encryption_key for done login
	let prep_login_out = PrepareLoginData::from_string(&prep_login_out.as_bytes()).unwrap();
	let master_key_encryption_key = prep_login_out.master_key_encryption_key;

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
	};

	let server_output = server_output.to_string().unwrap();

	//now save the values
	#[cfg(not(feature = "rust"))]
	let login_out = done_login(
		master_key_encryption_key.to_string().unwrap().as_str(), //the value comes from prepare login
		server_output.as_str(),
	);

	let login_out = KeyData::from_string(&login_out.as_bytes()).unwrap();

	let private_key = match login_out.private_key {
		PrivateKeyFormat::Ecies {
			key_id: _key_id,
			key,
		} => key,
	};

	format!("register done with private key: {:?}", private_key)
}

#[cfg(test)]
mod test
{
	use alloc::vec;

	use base64ct::{Base64, Encoding};
	use sendclose_crypto_common::group::{CreateData, GroupKeyServerOutput, GroupServerData};
	use sendclose_crypto_common::user::{
		DoneLoginServerKeysOutput,
		KeyDerivedData,
		PrepareLoginSaltServerOutput,
		RegisterData,
		UserPublicKeyData,
		UserVerifyKeyData,
	};

	use super::*;
	use crate::group::{get_group_data, prepare_create, GroupOutData};
	use crate::user::{done_login, prepare_login, register};
	use crate::util::KeyDataInt;

	pub(crate) fn simulate_server_prepare_login(derived: &KeyDerivedData) -> PrepareLoginSaltServerOutput
	{
		//and now try to login
		//normally the salt gets calc by the api
		let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();
		let salt_from_rand_value = sendclose_crypto_core::generate_salt(client_random_value);
		let salt_string = Base64::encode_string(&salt_from_rand_value);

		PrepareLoginSaltServerOutput {
			salt_string,
			derived_encryption_key_alg: derived.derived_alg.clone(),
			key_id: "1234".to_string(),
		}
	}

	pub(crate) fn simulate_server_done_login(data: RegisterData) -> DoneLoginServerKeysOutput
	{
		let RegisterData {
			derived,
			master_key,
		} = data;

		//get the server output back
		DoneLoginServerKeysOutput {
			encrypted_master_key: master_key.encrypted_master_key,
			encrypted_private_key: derived.encrypted_private_key,
			encrypted_sign_key: derived.encrypted_sign_key,
			public_key_string: derived.public_key,
			verify_key_string: derived.verify_key,
			keypair_encrypt_alg: derived.keypair_encrypt_alg,
			keypair_sign_alg: derived.keypair_sign_alg,
			keypair_encrypt_id: "abc".to_string(),
			keypair_sign_id: "dfg".to_string(),
		}
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn simulate_server_done_login_as_string(data: RegisterData) -> String
	{
		simulate_server_done_login(data).to_string().unwrap()
	}

	#[cfg(feature = "rust")]
	pub(crate) fn create_user() -> (KeyData, UserPublicKeyData, UserVerifyKeyData)
	{
		let password = "12345";

		let out_string = register(password).unwrap();

		let out = RegisterData::from_string(out_string.as_bytes()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		#[cfg(feature = "rust")]
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

		let user_public_key_data = UserPublicKeyData {
			public_key_pem: out.derived.public_key.to_string(),
			public_key_alg: out.derived.keypair_encrypt_alg.to_string(),
			public_key_id: "abc".to_string(),
		};

		let user_verify_key_data = UserVerifyKeyData {
			verify_key_pem: out.derived.verify_key.to_string(),
			verify_key_alg: out.derived.keypair_sign_alg.to_string(),
			verify_key_id: "dfg".to_string(),
		};

		let server_output = simulate_server_done_login(out);

		#[cfg(feature = "rust")]
		let done_login = done_login(&master_key_encryption_key, &server_output).unwrap();

		#[cfg(feature = "rust")]
		(done_login, user_public_key_data, user_verify_key_data)
	}

	#[cfg(feature = "rust")]
	pub(crate) fn create_group(user: &KeyData) -> GroupOutData
	{
		#[cfg(feature = "rust")]
		let group = prepare_create(&user.public_key).unwrap();
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		#[cfg(feature = "rust")]
		get_group_data(&user.private_key, &group_server_output).unwrap()
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_user() -> (KeyData, UserPublicKeyData, UserVerifyKeyData)
	{
		let password = "12345";

		let out_string = register(password);

		let out = RegisterData::from_string(out_string.as_bytes()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		let server_output_string = server_output.to_string().unwrap();
		#[cfg(not(feature = "rust"))]
		let prepare_login_string = prepare_login(password, server_output_string.as_str());

		let PrepareLoginData {
			master_key_encryption_key,
			..
		} = PrepareLoginData::from_string(prepare_login_string.as_bytes()).unwrap();

		let user_public_key_data = UserPublicKeyData {
			public_key_pem: out.derived.public_key.to_string(),
			public_key_alg: out.derived.keypair_encrypt_alg.to_string(),
			public_key_id: "abc".to_string(),
		};

		let user_verify_key_data = UserVerifyKeyData {
			verify_key_pem: out.derived.verify_key.to_string(),
			verify_key_alg: out.derived.keypair_sign_alg.to_string(),
			verify_key_id: "dfg".to_string(),
		};

		let server_output = simulate_server_done_login(out);

		#[cfg(not(feature = "rust"))]
		let done_login_string = done_login(
			master_key_encryption_key.to_string().unwrap().as_str(),
			server_output.to_string().unwrap().as_str(),
		);

		let done_login = KeyData::from_string(done_login_string.as_bytes()).unwrap();

		#[cfg(not(feature = "rust"))]
		(done_login, user_public_key_data, user_verify_key_data)
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_group(user: &KeyData) -> GroupOutData
	{
		#[cfg(not(feature = "rust"))]
		let group = prepare_create(user.public_key.to_string().unwrap().as_str());
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		#[cfg(not(feature = "rust"))]
		let group_data_string = get_group_data(
			user.private_key.to_string().unwrap().as_str(),
			group_server_output.to_string().unwrap().as_str(),
		);

		GroupOutData::from_string(group_data_string.as_bytes()).unwrap()
	}

	#[test]
	fn test_register_test()
	{
		register_test();
	}
}
