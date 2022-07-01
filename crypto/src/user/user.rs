use base64ct::{Base64, Encoding};
use sendclose_crypto_common::user::{KeyData, MasterKeyFormat, PrepareLoginData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, VerifyKeyFormat};
use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error, Pk, SignK, Sk, VerifyK};

use crate::err_to_msg;
use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally};

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
	use super::*;

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string());

		println!("{}", out);
	}
}
