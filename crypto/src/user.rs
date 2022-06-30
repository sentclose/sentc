use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;
#[cfg(not(feature = "rust"))]
use sendclose_crypto_common::user::MasterKeyFormat;
use sendclose_crypto_common::user::{ChangePasswordData, DoneLoginInput, KeyDerivedData, MasterKey, RegisterData};
#[cfg(not(feature = "rust"))]
use sendclose_crypto_common::user::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, VerifyKeyFormat};

use crate::core::user::{
	change_password as change_password_core,
	done_login as done_login_core,
	prepare_login as prepare_login_core,
	register as register_core,
};
#[cfg(not(feature = "rust"))]
use crate::err_to_msg;
use crate::{alg, ClientRandomValue, DeriveAuthKeyForAuth, DeriveMasterKeyForAuth, Error, HashedAuthenticationKey, Pk, SignK, Sk, VerifyK};

//this functions are used for decoding and encoding the internally values for and from the other implementations
//we can't work with the enums from the core user mod directly because they must be encoded to base64

pub struct DoneLoginOutput
{
	pub private_key: Sk,
	pub sign_key: SignK,
	pub public_key: Pk,
	pub verify_key: VerifyK,
}

fn register_internally(password: String) -> Result<String, Error>
{
	let out = register_core(password)?;

	//transform the register output into json

	//1. encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//2. export the public keys (decrypt and verify) to a key format
	let public_key = match out.public_key {
		//match against the public key variants
		Pk::Ecies(k) => export_key_to_pem(&k)?,
	};

	let verify_key = match out.verify_key {
		VerifyK::Ed25519(k) => export_key_to_pem(&k)?,
	};

	//3. export the random value
	let client_random_value = match out.client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(&v),
	};

	//4. export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = match out.hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(&h),
	};

	//5. create the structs
	let master_key = MasterKey {
		encrypted_master_key,
		master_key_alg: out.master_key_alg.to_string(),
		encrypted_master_key_alg: out.master_key_info.alg.to_string(),
	};

	let derived = KeyDerivedData {
		public_key,
		verify_key,
		derived_alg: out.derived_alg.to_string(),
		client_random_value,
		encrypted_private_key,
		encrypted_sign_key,
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		keypair_sign_alg: out.keypair_sign_alg.to_string(),
		hashed_authentication_key,
	};

	let register_out = RegisterData {
		master_key,
		derived,
	};

	//use always to string, even for rust feature enable because this data is for the server
	Ok(register_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

#[cfg(feature = "rust")]
pub fn register(password: String) -> Result<String, Error>
{
	register_internally(password)
}

#[cfg(not(feature = "rust"))]
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

fn prepare_login_internally(
	password: String,
	salt_string: String,
	derived_encryption_key_alg: String,
) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	let salt = Base64::decode_vec(salt_string.as_str()).map_err(|_| Error::DecodeSaltFailed)?;
	let result = prepare_login_core(password, &salt, derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = match result.auth_key {
		DeriveAuthKeyForAuth::Argon2(k) => Base64::encode_string(&k),
	};

	Ok((auth_key, result.master_key_encryption_key))
}

#[cfg(feature = "rust")]
pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	prepare_login_internally(password, salt_string, derived_encryption_key_alg)
}

#[cfg(not(feature = "rust"))]
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

	let master_key_out = match master_key_encryption_key.to_string() {
		Ok(v) => v,
		Err(_e) => return err_to_msg(Error::JsonToStringFailed),
	};

	//the impl needs to split it and give the master_key_encryption_key back for done login
	format!("{{\"auth_key\": {}, \"master_key_encryption_key\": \"{}\"}}", auth_key, master_key_out)
}

fn done_login_internally(master_key_encryption: &DeriveMasterKeyForAuth, server_output: String) -> Result<DoneLoginOutput, Error>
{
	let server_output = DoneLoginInput::from_string(server_output.as_bytes()).map_err(|_| Error::LoginServerOutputWrong)?;

	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_master_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = Base64::decode_vec(server_output.encrypted_sign_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;

	let out = done_login_core(
		&master_key_encryption,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.keypair_encrypt_alg.as_str(),
		&encrypted_sign_key,
		server_output.keypair_sign_alg.as_str(),
	)?;

	//now prepare the public and verify key for use

	let public_key = import_key_from_pem(server_output.public_key_string)?;
	let verify_key = import_key_from_pem(server_output.verify_key_string)?;

	let public_key = match server_output.keypair_encrypt_alg.as_str() {
		alg::asym::ecies::ECIES_OUTPUT => {
			let public_key = public_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;
			Pk::Ecies(public_key)
		},
		_ => return Err(Error::AlgNotFound),
	};

	let verify_key = match server_output.keypair_sign_alg.as_str() {
		alg::sign::ed25519::ED25519_OUTPUT => {
			let verify_key = verify_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;
			VerifyK::Ed25519(verify_key)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok(DoneLoginOutput {
		private_key: out.private_key,
		sign_key: out.sign_key,
		public_key,
		verify_key,
	})
}

#[cfg(feature = "rust")]
pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: String) -> Result<DoneLoginOutput, Error>
{
	done_login_internally(&master_key_encryption, server_output)
}

#[cfg(not(feature = "rust"))]
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
			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = match mk.as_bytes().try_into() {
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

fn change_password_internally(
	old_pw: String,
	new_pw: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> Result<String, Error>
{
	let encrypted_master_key = Base64::decode_vec(encrypted_master_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let old_salt = Base64::decode_vec(old_salt.as_str()).map_err(|_| Error::DecodeSaltFailed)?;

	let output = change_password_core(old_pw, new_pw, &old_salt, &encrypted_master_key, derived_encryption_key_alg.as_str())?;

	//prepare for the server
	let new_encrypted_master_key = Base64::encode_string(&output.master_key_info.encrypted_master_key);

	let new_client_random_value = match output.client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(&v),
	};

	//the 16 bytes of the org. hashed key
	let new_hashed_authentication_key = match output.hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(&h),
	};

	let old_auth_key = match output.old_auth_key {
		DeriveAuthKeyForAuth::Argon2(h) => Base64::encode_string(&h),
	};

	let pw_change_out = ChangePasswordData {
		new_derived_alg: output.derived_alg.to_string(),
		new_encrypted_master_key,
		new_client_random_value,
		new_hashed_authentication_key,
		new_encrypted_master_key_alg: output.master_key_info.alg.to_string(),
		old_auth_key,
	};

	Ok(pw_change_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

#[cfg(feature = "rust")]
pub fn change_password(
	old_pw: String,
	new_pw: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> Result<String, Error>
{
	change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

#[cfg(not(feature = "rust"))]
pub fn change_password(old_pw: String, new_pw: String, old_salt: String, encrypted_master_key: String, derived_encryption_key_alg: String) -> String
{
	match change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg) {
		Err(e) => return err_to_msg(e),
		Ok(v) => v,
	}
}

#[cfg(not(feature = "rust"))]
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

#[cfg(not(feature = "rust"))]
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

#[cfg(not(feature = "rust"))]
pub(crate) fn export_private_key(private_key: Sk) -> PrivateKeyFormat
{
	match private_key {
		Sk::Ecies(k) => {
			let private_key_string = Base64::encode_string(&k);

			PrivateKeyFormat::Ecies(private_key_string)
		},
	}
}

#[cfg(not(feature = "rust"))]
pub(crate) fn export_public_key(public_key: Pk) -> PublicKeyFormat
{
	match public_key {
		Pk::Ecies(k) => {
			let public_key_string = Base64::encode_string(&k);

			PublicKeyFormat::Ecies(public_key_string)
		},
	}
}

#[cfg(not(feature = "rust"))]
pub(crate) fn export_sign_key(sign_key: SignK) -> SignKeyFormat
{
	match sign_key {
		SignK::Ed25519(k) => {
			let sign_key_string = Base64::encode_string(&k);

			SignKeyFormat::Ed25519(sign_key_string)
		},
	}
}

#[cfg(not(feature = "rust"))]
pub(crate) fn export_verify_key(verify_key: VerifyK) -> VerifyKeyFormat
{
	match verify_key {
		VerifyK::Ed25519(k) => {
			let verify_key_string = Base64::encode_string(&k);

			VerifyKeyFormat::Ed25519(verify_key_string)
		},
	}
}

pub(crate) fn export_key_to_pem(key: &[u8]) -> Result<String, Error>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| Error::ExportingPublicKeyFailed)?;

	Ok(key)
}

pub(crate) fn import_key_from_pem(pem: String) -> Result<Vec<u8>, Error>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| Error::ImportingPublicKeyFailed)?;

	Ok(data)
}

#[cfg(test)]
mod test
{
	use super::*;

	#[cfg(feature = "rust")]
	mod test_rust_feature
	{
		use super::*;

		#[test]
		fn test_register()
		{
			let password = "abc*èéöäüê";

			#[cfg(feature = "rust")]
			let out = register(password.to_string()).unwrap();

			println!("{}", out);
		}
	}

	#[cfg(not(feature = "rust"))]
	mod test_non_rust_feature
	{
		use super::*;

		#[test]
		fn test_register()
		{
			let password = "abc*èéöäüê";

			#[cfg(not(feature = "rust"))]
			let out = register(password.to_string());

			println!("{}", out);
		}
	}
}
