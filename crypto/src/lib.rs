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
	use sendclose_crypto_common::user::{DoneLoginServerKeysOutput, KeyDerivedData, PrepareLoginSaltServerOutput, RegisterData};

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
	pub(crate) fn create_user() -> KeyDataInt
	{
		let password = "12345";

		let out = register(password).unwrap();

		let out = RegisterData::from_string(out.as_bytes()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		#[cfg(feature = "rust")]
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		#[cfg(feature = "rust")]
		done_login(&master_key_encryption_key, &server_output).unwrap()
	}

	#[cfg(feature = "rust")]
	pub(crate) fn create_group(user: &KeyDataInt) -> GroupOutData
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

	#[test]
	fn test_register_test()
	{
		register_test();
	}
}

/*
pub fn aes() -> String
{
	//aes
	aes_intern()
}

fn aes_intern() -> String
{
	let test = "plaintext message";
	let test2 = "plaintext message2";

	let res = alg::sym::aes_gcm::generate_and_encrypt(test.as_ref());

	let (output, encrypted) = match res {
		Err(e) => return format!("Error for encrypt test 1: {:?}", e),
		Ok(v) => v,
	};

	let res = alg::sym::aes_gcm::encrypt(&output.key, test2.as_ref());

	let encrypted2 = match res {
		Err(e) => return format!("Error for encrypt test 2: {:?}", e),
		Ok(v) => v,
	};

	//decrypt
	let res = alg::sym::aes_gcm::decrypt(&output.key, &encrypted);

	let decrypted = match res {
		Err(e) => return format!("Error for decrypt test 1: {:?}", e),
		Ok(v) => v,
	};

	let res = alg::sym::aes_gcm::decrypt(&output.key, &encrypted2);

	let decrypted2 = match res {
		Err(e) => return format!("Error for decrypt test 2: {:?}", e),
		Ok(v) => v,
	};

	assert_eq!(&decrypted, b"plaintext message");
	assert_eq!(&decrypted2, b"plaintext message2");

	let one = std::str::from_utf8(&decrypted).unwrap().to_owned();
	let two = std::str::from_utf8(&decrypted2).unwrap();

	one + " " + two
}

pub fn ecdh() -> String
{
	// Alice
	//let (alice_secret, alice_pk) = alg::asym::ecies::generate_static_keypair();

	// Bob
	let bob_out = alg::asym::ecies::generate_static_keypair();

	let bob_secret = bob_out.sk;
	let bob_pk = bob_out.pk;

	//Alice create a msg for Bob's public key
	let alice_msg = "Hello Bob";
	let alice_encrypted = alg::asym::ecies::encrypt(&bob_pk, alice_msg.as_ref()).unwrap();

	//Bob decrypt it with his own private key
	let bob_decrypt = alg::asym::ecies::decrypt(&bob_secret, &alice_encrypted).unwrap();
	let bob_msg = std::str::from_utf8(&bob_decrypt).unwrap();

	assert_eq!(bob_msg, alice_msg);

	alice_msg.to_string() + " " + bob_msg
}

pub fn argon() -> String
{
	let master_key = alg::sym::aes_gcm::generate_key().unwrap();

	let key = match master_key.key {
		SymKey::Aes(k) => k,
	};

	let out = alg::pw_hash::argon2::derived_keys_from_password(b"abc", &key).unwrap();

	let encrypted_master_key = out.master_key_info.encrypted_master_key;

	Base64::encode_string(&encrypted_master_key)
}

pub fn argon_pw_encrypt() -> String
{
	let test = "plaintext message";

	//encrypt a value with a password, in prod this might be the key of the content
	let (aes_key_for_encrypt, salt) = alg::pw_hash::argon2::password_to_encrypt(b"my fancy password").unwrap();

	let encrypted = alg::sym::aes_gcm::encrypt_with_generated_key(&aes_key_for_encrypt, test.as_ref()).unwrap();

	//decrypt a value with password
	let aes_key_for_decrypt = alg::pw_hash::argon2::password_to_decrypt(b"my fancy password", &salt).unwrap();

	let decrypted = alg::sym::aes_gcm::decrypt_with_generated_key(&aes_key_for_decrypt, &encrypted).unwrap();

	let str = std::str::from_utf8(&decrypted).unwrap();

	assert_eq!(str, test);

	str.to_owned()
}

pub fn sign() -> String
{
	let test = "plaintext message";

	let out = alg::sign::ed25519::generate_key_pair();

	let out = match out {
		Err(_e) => return String::from("error"),
		Ok(o) => o,
	};

	let data_with_sig = alg::sign::ed25519::sign(&out.sign_key, test.as_bytes()).unwrap();

	let check = alg::sign::ed25519::verify(&out.verify_key, &data_with_sig).unwrap();

	assert_eq!(check, true);

	format!("check was: {}", check)
}


#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_aes()
	{
		let str = aes();

		assert_eq!(str, "plaintext message plaintext message2");
	}

	#[test]
	fn test_ecdh()
	{
		let str = ecdh();

		assert_eq!(str, "Hello Bob Hello Bob");
	}

	#[test]
	fn test_register()
	{
		let str = argon();

		assert_ne!(str.len(), 0);
	}

	#[test]
	fn test_pw_encrypt()
	{
		let str = argon_pw_encrypt();

		assert_eq!(str, "plaintext message");
	}

	#[test]
	fn test_sign()
	{
		let str = sign();

		assert_eq!(str, "check was: true");
	}

	#[test]
	fn test_register_full()
	{
		let str = register_test();

		assert_eq!(str, "register sign result was: true and decrypted text was: Hello world üöäéèßê°");
	}
}
*/
