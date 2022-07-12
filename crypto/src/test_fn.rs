use alloc::format;
use alloc::string::{String, ToString};

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{DoneLoginServerKeysOutput, PrepareLoginSaltServerOutput, RegisterData};
#[cfg(feature = "rust")]
use sentc_crypto_core::Sk;

use crate::user::{done_login, prepare_login, register};
use crate::util::client_random_value_from_string;
#[cfg(not(feature = "rust"))]
use crate::{KeyData, PrivateKeyFormat};

#[cfg(feature = "rust")]
pub fn register_test_full() -> String
{
	let password = "abc*èéöäüê";

	#[cfg(feature = "rust")]
	let out = register(password).unwrap();

	let out = RegisterData::from_string(out.as_str()).unwrap();
	let RegisterData {
		derived,
		master_key,
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();

	let salt_from_rand_value = sentc_crypto_core::generate_salt(client_random_value);
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
pub fn register_test_full() -> String
{
	let password = "abc*èéöäüê";

	#[cfg(not(feature = "rust"))]
	let out = register(password).unwrap();

	let out = RegisterData::from_string(out.as_str()).unwrap();
	let RegisterData {
		derived,
		master_key,
	} = out;

	//and now try to login
	//normally the salt gets calc by the api
	let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();

	let salt_from_rand_value = sentc_crypto_core::generate_salt(client_random_value);
	let salt_from_rand_value = Base64::encode_string(&salt_from_rand_value);

	let server_output = PrepareLoginSaltServerOutput {
		salt_string: salt_from_rand_value,
		derived_encryption_key_alg: derived.derived_alg.clone(),
		key_id: "1234".to_string(),
	};

	//back to the client, send prep login out string to the server if it is no err
	#[cfg(not(feature = "rust"))]
	let (_auth_key, master_key_encryption_key) = prepare_login(password, server_output.to_string().unwrap().as_str()).unwrap();

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
		master_key_encryption_key.as_str(), //the value comes from prepare login
		server_output.as_str(),
	)
	.unwrap();

	let login_out = KeyData::from_string(&login_out.as_str()).unwrap();

	let private_key = match login_out.private_key {
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
	let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();
	let salt_from_rand_value = sentc_crypto_core::generate_salt(client_random_value);
	let salt_string = Base64::encode_string(&salt_from_rand_value);

	let prep = PrepareLoginSaltServerOutput {
		salt_string,
		derived_encryption_key_alg: derived.derived_alg.clone(),
		key_id: "1234".to_string(),
	};

	prep.to_string().unwrap()
}

#[cfg(not(feature = "rust"))]
pub fn simulate_server_done_login(register_data: &str) -> String
{
	let RegisterData {
		derived,
		master_key,
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
	};

	done_login_server_out.to_string().unwrap()
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_register_test()
	{
		register_test_full();
	}

	#[cfg(not(feature = "rust"))]
	#[test]
	fn test_register_fn()
	{
		let password = "12345";

		let out_string = register(password).unwrap();

		let prep_login_in = simulate_server_prepare_login(out_string.as_str());
		let (_auth_key, master_key_encryption_key) = prepare_login(password, prep_login_in.as_str()).unwrap();

		let server_output = simulate_server_done_login(out_string.as_str());

		let done_login_string = done_login(master_key_encryption_key.as_str(), server_output.as_str()).unwrap();

		let _done_login = KeyData::from_string(done_login_string.as_str()).unwrap();
	}
}
