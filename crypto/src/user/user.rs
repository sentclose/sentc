use alloc::string::String;

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::user::{KeyData, MasterKeyFormat, PrepareLoginData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, VerifyKeyFormat};
use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error, Pk, SignK, Sk, VerifyK};

use crate::err_to_msg;
use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally, reset_password_internally};

pub fn register(password: String) -> String
{
	match register_internally(password) {
		Err(e) => {
			//create the err to json
			return err_to_msg(e);
		},
		Ok(o) => o,
	}
}

pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> String
{
	let (auth_key, master_key_encryption_key) = match prepare_login_internally(password, salt_string, derived_encryption_key_alg) {
		Err(e) => return err_to_msg(e),
		Ok(o) => o,
	};

	//return the encryption key for the master key to the app and then use it for done login
	let master_key_encryption_key = match master_key_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => {
			let key = Base64::encode_string(&k);

			MasterKeyFormat::Argon2(key)
		},
	};

	let output = PrepareLoginData {
		auth_key,
		master_key_encryption_key,
	};

	match output.to_string() {
		Ok(v) => v,
		Err(_e) => return err_to_msg(Error::JsonToStringFailed),
	}
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> String
{
	let master_key_encryption = match MasterKeyFormat::from_string(master_key_encryption.as_bytes()) {
		Ok(v) => v,
		Err(_e) => return err_to_msg(Error::JsonParseFailed),
	};

	let master_key_encryption = match master_key_encryption {
		MasterKeyFormat::Argon2(mk) => {
			let mk = match Base64::decode_vec(mk.as_str()) {
				Ok(m) => m,
				Err(_e) => return err_to_msg(Error::KeyDecryptFailed),
			};

			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = match mk.try_into() {
				Err(_e) => return err_to_msg(Error::KeyDecryptFailed),
				Ok(k) => k,
			};

			DeriveMasterKeyForAuth::Argon2(master_key_encryption_key)
		},
	};

	let result = done_login_internally(&master_key_encryption, server_output);

	let result = match result {
		Ok(v) => v,
		Err(e) => return err_to_msg(e),
	};

	let private_key = export_private_key(result.private_key);
	//the public key was decode from pem before by the done_login_internally function, so we can import it later one without checking err
	let public_key = export_public_key(result.public_key);
	let sign_key = export_sign_key(result.sign_key);
	let verify_key = export_verify_key(result.verify_key);

	let output = KeyData {
		private_key,
		sign_key,
		public_key,
		verify_key,
		keypair_encrypt_id: result.keypair_encrypt_id,
		keypair_sign_id: result.keypair_sign_id,
	};

	match output.to_string() {
		Ok(v) => v,
		Err(_e) => return err_to_msg(Error::JsonToStringFailed),
	}
}

pub fn change_password(old_pw: String, new_pw: String, old_salt: String, encrypted_master_key: String, derived_encryption_key_alg: String) -> String
{
	match change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg) {
		Err(e) => return err_to_msg(e),
		Ok(v) => v,
	}
}

pub fn reset_password(new_password: String, decrypted_private_key: String, decrypted_sign_key: String) -> String
{
	let decrypted_private_key = match import_private_key(decrypted_private_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let decrypted_sign_key = match import_sign_key(decrypted_sign_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match reset_password_internally(new_password, &decrypted_private_key, &decrypted_sign_key) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub(crate) fn import_private_key(private_key_string: String) -> Result<Sk, Error>
{
	let private_key_format = PrivateKeyFormat::from_string(private_key_string.as_bytes()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

	match private_key_format {
		PrivateKeyFormat::Ecies(s) => {
			//to bytes via base64
			let bytes = Base64::decode_vec(s.as_str()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

			let private_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingPrivateKeyFailed)?;

			Ok(Sk::Ecies(private_key))
		},
	}
}

pub(crate) fn import_public_key(public_key_string: String) -> Result<Pk, Error>
{
	let public_key_format = PublicKeyFormat::from_string(public_key_string.as_bytes()).map_err(|_| Error::ImportPublicKeyFailed)?;

	match public_key_format {
		PublicKeyFormat::Ecies(s) => {
			let bytes = Base64::decode_vec(s.as_str()).map_err(|_| Error::ImportPublicKeyFailed)?;

			let key = bytes.try_into().map_err(|_| Error::ImportPublicKeyFailed)?;

			Ok(Pk::Ecies(key))
		},
	}
}

pub(crate) fn import_sign_key(sign_key_string: String) -> Result<SignK, Error>
{
	let sign_key_format = SignKeyFormat::from_string(sign_key_string.as_bytes()).map_err(|_| Error::ImportingSignKeyFailed)?;

	match sign_key_format {
		SignKeyFormat::Ed25519(s) => {
			//to bytes via base64
			let bytes = Base64::decode_vec(s.as_str()).map_err(|_| Error::ImportingSignKeyFailed)?;

			let sign_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingSignKeyFailed)?;

			Ok(SignK::Ed25519(sign_key))
		},
	}
}

pub(crate) fn export_private_key(private_key: Sk) -> PrivateKeyFormat
{
	match private_key {
		Sk::Ecies(k) => {
			let private_key_string = Base64::encode_string(&k);

			PrivateKeyFormat::Ecies(private_key_string)
		},
	}
}

pub(crate) fn export_public_key(public_key: Pk) -> PublicKeyFormat
{
	match public_key {
		Pk::Ecies(k) => {
			let public_key_string = Base64::encode_string(&k);

			PublicKeyFormat::Ecies(public_key_string)
		},
	}
}

pub(crate) fn export_sign_key(sign_key: SignK) -> SignKeyFormat
{
	match sign_key {
		SignK::Ed25519(k) => {
			let sign_key_string = Base64::encode_string(&k);

			SignKeyFormat::Ed25519(sign_key_string)
		},
	}
}

pub(crate) fn export_verify_key(verify_key: VerifyK) -> VerifyKeyFormat
{
	match verify_key {
		VerifyK::Ed25519(k) => {
			let verify_key_string = Base64::encode_string(&k);

			VerifyKeyFormat::Ed25519(verify_key_string)
		},
	}
}

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;

	use sendclose_crypto_common::user::{ChangePasswordData, RegisterData};

	use super::*;
	use crate::test::{simulate_server_done_login, simulate_server_prepare_login};

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string());

		std::println!("{}", out);
	}

	#[test]
	fn test_register_and_login()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string());

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		//back to the client, send prep login out string to the server if it is no err
		let prep_login_out = prepare_login(password.to_string(), salt_from_rand_value, out.derived.derived_alg.clone());

		//and get the master_key_encryption_key for done login
		let prep_login_out = PrepareLoginData::from_string(&prep_login_out.as_bytes()).unwrap();
		let master_key_encryption_key = prep_login_out.master_key_encryption_key;

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(
			master_key_encryption_key.to_string().unwrap(), //the value comes from prepare login
			server_output,
		);

		let login_out = KeyData::from_string(&login_out.as_bytes()).unwrap();

		let private_key = match login_out.private_key {
			PrivateKeyFormat::Ecies(k) => k,
		};

		assert_ne!(private_key, "");
	}

	#[test]
	fn test_change_password()
	{
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(password.to_string());

		let out = RegisterData::from_string(out.as_bytes()).unwrap();

		let salt_from_rand_value = simulate_server_prepare_login(&out.derived);

		let pw_change_out = change_password(
			password.to_string(),
			new_password.to_string(),
			salt_from_rand_value,
			out.master_key.encrypted_master_key.clone(),
			out.derived.derived_alg,
		);

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_bytes()).unwrap();

		assert_ne!(pw_change_out.new_client_random_value, out.derived.client_random_value);

		assert_ne!(pw_change_out.new_encrypted_master_key, out.master_key.encrypted_master_key);
	}
}
