use alloc::string::String;

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::user::DoneLoginInput;
use sendclose_crypto_core::{DeriveMasterKeyForAuth, Error, Pk, SignK, Sk, VerifyK};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

use crate::err_to_msg;
use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally, reset_password_internally};

#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String),
}

impl MasterKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub struct PrepareLoginData
{
	pub auth_key: String,
	pub master_key_encryption_key: MasterKeyFormat,
}

impl PrepareLoginData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum PrivateKeyFormat
{
	Ecies
	{
		key: String, key_id: String
	},
}

impl PrivateKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum PublicKeyFormat
{
	Ecies
	{
		key: String, key_id: String
	},
}

impl PublicKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum SignKeyFormat
{
	Ed25519
	{
		key: String, key_id: String
	},
}

impl SignKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyFormat
{
	Ed25519
	{
		key: String, key_id: String
	},
}

impl VerifyKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

/**
# Key data to communicate with other ffi programs via Strings

This data must be serialized for exporting and deserialized for import
*/
#[derive(Serialize, Deserialize)]
pub struct KeyData
{
	pub private_key: PrivateKeyFormat,
	pub public_key: PublicKeyFormat,
	pub sign_key: SignKeyFormat,
	pub verify_key: VerifyKeyFormat,
}

impl KeyData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

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

	let server_output = match DoneLoginInput::from_string(server_output.as_bytes()).map_err(|_| Error::LoginServerOutputWrong) {
		Ok(v) => v,
		Err(e) => return err_to_msg(e),
	};

	let result = done_login_internally(&master_key_encryption, &server_output);

	let result = match result {
		Ok(v) => v,
		Err(e) => return err_to_msg(e),
	};

	let private_key = export_private_key(result.private_key, result.keypair_encrypt_id.clone());
	//the public key was decode from pem before by the done_login_internally function, so we can import it later one without checking err
	let public_key = export_public_key(result.public_key, result.keypair_encrypt_id);
	let sign_key = export_sign_key(result.sign_key, result.keypair_sign_id.clone());
	let verify_key = export_verify_key(result.verify_key, result.keypair_sign_id);

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

pub fn reset_password(new_password: String, decrypted_private_key: String, decrypted_sign_key: String) -> String
{
	let (decrypted_private_key, _) = match import_private_key(decrypted_private_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let (decrypted_sign_key, _) = match import_sign_key(decrypted_sign_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match reset_password_internally(new_password, &decrypted_private_key, &decrypted_sign_key) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub(crate) fn import_private_key(private_key_string: String) -> Result<(Sk, String), Error>
{
	let private_key_format = PrivateKeyFormat::from_string(private_key_string.as_bytes()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

	match private_key_format {
		PrivateKeyFormat::Ecies {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

			let private_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingPrivateKeyFailed)?;

			Ok((Sk::Ecies(private_key), key_id))
		},
	}
}

pub(crate) fn import_public_key(public_key_string: String) -> Result<(Pk, String), Error>
{
	let public_key_format = PublicKeyFormat::from_string(public_key_string.as_bytes()).map_err(|_| Error::ImportPublicKeyFailed)?;

	match public_key_format {
		PublicKeyFormat::Ecies {
			key_id,
			key,
		} => {
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportPublicKeyFailed)?;

			let key = bytes.try_into().map_err(|_| Error::ImportPublicKeyFailed)?;

			Ok((Pk::Ecies(key), key_id))
		},
	}
}

pub(crate) fn import_sign_key(sign_key_string: String) -> Result<(SignK, String), Error>
{
	let sign_key_format = SignKeyFormat::from_string(sign_key_string.as_bytes()).map_err(|_| Error::ImportingSignKeyFailed)?;

	match sign_key_format {
		SignKeyFormat::Ed25519 {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportingSignKeyFailed)?;

			let sign_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingSignKeyFailed)?;

			Ok((SignK::Ed25519(sign_key), key_id))
		},
	}
}

pub(crate) fn export_private_key(private_key: Sk, key_id: String) -> PrivateKeyFormat
{
	match private_key {
		Sk::Ecies(k) => {
			let private_key_string = Base64::encode_string(&k);

			PrivateKeyFormat::Ecies {
				key_id,
				key: private_key_string,
			}
		},
	}
}

pub(crate) fn export_public_key(public_key: Pk, key_id: String) -> PublicKeyFormat
{
	match public_key {
		Pk::Ecies(k) => {
			let public_key_string = Base64::encode_string(&k);

			PublicKeyFormat::Ecies {
				key_id,
				key: public_key_string,
			}
		},
	}
}

pub(crate) fn export_sign_key(sign_key: SignK, key_id: String) -> SignKeyFormat
{
	match sign_key {
		SignK::Ed25519(k) => {
			let sign_key_string = Base64::encode_string(&k);

			SignKeyFormat::Ed25519 {
				key_id,
				key: sign_key_string,
			}
		},
	}
}

pub(crate) fn export_verify_key(verify_key: VerifyK, key_id: String) -> VerifyKeyFormat
{
	match verify_key {
		VerifyK::Ed25519(k) => {
			let verify_key_string = Base64::encode_string(&k);

			VerifyKeyFormat::Ed25519 {
				key_id,
				key: verify_key_string,
			}
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
	use crate::test::{simulate_server_done_login_as_string, simulate_server_prepare_login};

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

		let server_output = simulate_server_done_login_as_string(out);

		//now save the values
		let login_out = done_login(
			master_key_encryption_key.to_string().unwrap(), //the value comes from prepare login
			server_output,
		);

		let login_out = KeyData::from_string(&login_out.as_bytes()).unwrap();

		let private_key = match login_out.private_key {
			PrivateKeyFormat::Ecies {
				key_id: _,
				key,
			} => key,
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
