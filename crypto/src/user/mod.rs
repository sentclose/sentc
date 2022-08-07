//! # Handle user
//!
//! this functions are used for decoding and encoding the internally values for and from the other implementations
//! we can't work with the enums from the core user mod directly because they must be encoded to base64
//!
//! If rust feature is enabled the rust functions are used. The return is no longer just a json string but rust structs and enums to work with

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{
	ChangePasswordData,
	DoneLoginServerInput,
	DoneLoginServerKeysOutput,
	KeyDerivedData,
	MasterKey,
	MultipleLoginServerOutput,
	PrepareLoginSaltServerOutput,
	PrepareLoginServerInput,
	RegisterData,
	RegisterServerOutput,
	ResetPasswordData,
	UserIdentifierAvailableServerInput,
	UserIdentifierAvailableServerOutput,
	UserPublicKeyData,
	UserVerifyKeyData,
};
use sentc_crypto_common::UserId;
use sentc_crypto_core::{user as core_user, DeriveMasterKeyForAuth};

use crate::util::{
	client_random_value_to_string,
	derive_auth_key_for_auth_to_string,
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	hashed_authentication_key_to_string,
	import_public_key_from_pem_with_alg,
	import_verify_key_from_pem_with_alg,
	KeyDataInt,
	PrivateKeyFormatInt,
	PublicKeyFormatInt,
	SignKeyFormatInt,
	VerifyKeyFormatInt,
};
use crate::util_pub::{generate_salt_from_base64, handle_server_response};
use crate::SdkError;

#[cfg(feature = "rust")]
mod user_rust;

#[cfg(not(feature = "rust"))]
mod user;

//export when rust feature is not enabled
#[cfg(not(feature = "rust"))]
pub use self::user::{
	change_password,
	done_check_user_identifier_available,
	done_login,
	done_register,
	prepare_check_user_identifier_available,
	prepare_login,
	prepare_login_start,
	prepare_update_user_keys,
	register,
	reset_password,
	MasterKeyFormat,
};
//export when rust feature is enabled
#[cfg(feature = "rust")]
pub use self::user_rust::{
	change_password,
	done_check_user_identifier_available,
	done_login,
	done_register,
	prepare_check_user_identifier_available,
	prepare_login,
	prepare_login_start,
	prepare_update_user_keys,
	register,
	reset_password,
};

/**
# Prepare the server input for the check
*/
fn prepare_check_user_identifier_available_internally(user_identifier: &str) -> Result<String, SdkError>
{
	UserIdentifierAvailableServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkError::JsonToStringFailed)
}

fn done_check_user_identifier_available_internally(server_output: &str) -> Result<bool, SdkError>
{
	let server_output: UserIdentifierAvailableServerOutput = handle_server_response(server_output)?;

	Ok(server_output.available)
}

/**
# Prepare the register input incl. keys
*/
fn register_internally(user_identifier: &str, password: &str) -> Result<String, SdkError>
{
	let out = core_user::register(password)?;

	//transform the register output into json

	//1. encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//2. export the public keys (decrypt and verify) to a key format
	let public_key = export_raw_public_key_to_pem(&out.public_key)?;

	let verify_key = export_raw_verify_key_to_pem(&out.verify_key)?;

	//3. export the random value
	let client_random_value = client_random_value_to_string(&out.client_random_value);

	//4. export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

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
		user_identifier: user_identifier.to_string(),
	};

	//use always to string, even for rust feature enable because this data is for the server
	Ok(register_out
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?)
}

fn done_register_internally(server_output: &str) -> Result<UserId, SdkError>
{
	let out: RegisterServerOutput = handle_server_response(server_output)?;

	Ok(out.user_id)
}

/**
# prepare the data for the server req

*/
fn prepare_login_start_internally(user_identifier: &str) -> Result<String, SdkError>
{
	PrepareLoginServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkError::JsonToStringFailed)
}

/**
# Starts the login process

1. Get the auth key and the master key encryption key from the password.
2. Send the auth key to the server to get the DoneLoginInput back
 */
fn prepare_login_internally(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, DeriveMasterKeyForAuth), SdkError>
{
	let server_output: PrepareLoginSaltServerOutput = handle_server_response(server_output)?;

	let salt = Base64::decode_vec(server_output.salt_string.as_str()).map_err(|_| SdkError::DecodeSaltFailed)?;
	let result = core_user::prepare_login(password, &salt, server_output.derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = derive_auth_key_for_auth_to_string(&result.auth_key);

	let auth_key = DoneLoginServerInput {
		auth_key,
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkError::JsonToStringFailed)?;

	Ok((auth_key, result.master_key_encryption_key))
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private and sign keys, in pem exported public and verify keys
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public and verify keys to the internal format
 */
fn done_login_internally(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &str) -> Result<KeyDataInt, SdkError>
{
	let server_output: DoneLoginServerKeysOutput = handle_server_response(server_output)?;

	done_login_internally_with_server_out(master_key_encryption, &server_output)
}

fn done_login_internally_with_server_out(
	master_key_encryption: &DeriveMasterKeyForAuth,
	server_output: &DoneLoginServerKeysOutput,
) -> Result<KeyDataInt, SdkError>
{
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_master_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = Base64::decode_vec(server_output.encrypted_sign_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;

	let out = core_user::done_login(
		&master_key_encryption,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.keypair_encrypt_alg.as_str(),
		&encrypted_sign_key,
		server_output.keypair_sign_alg.as_str(),
	)?;

	//now prepare the public and verify key for use
	let public_key = import_public_key_from_pem_with_alg(
		server_output.public_key_string.as_str(),
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	let verify_key = import_verify_key_from_pem_with_alg(
		server_output.verify_key_string.as_str(),
		server_output.keypair_sign_alg.as_str(),
	)?;

	//export this too, so the user can verify the own data
	let exported_public_key = UserPublicKeyData {
		public_key_pem: server_output.public_key_string.to_string(),
		public_key_alg: server_output.keypair_encrypt_alg.to_string(),
		public_key_id: server_output.keypair_encrypt_id.clone(),
	};

	let exported_verify_key = UserVerifyKeyData {
		verify_key_pem: server_output.verify_key_string.to_string(),
		verify_key_alg: server_output.keypair_sign_alg.to_string(),
		verify_key_id: server_output.keypair_sign_id.clone(),
	};

	Ok(KeyDataInt {
		jwt: server_output.jwt.to_string(),
		user_id: server_output.user_id.to_string(),
		private_key: PrivateKeyFormatInt {
			key_id: server_output.keypair_encrypt_id.clone(),
			key: out.private_key,
		},
		sign_key: SignKeyFormatInt {
			key_id: server_output.keypair_sign_id.clone(),
			key: out.sign_key,
		},
		public_key: PublicKeyFormatInt {
			key_id: server_output.keypair_encrypt_id.clone(),
			key: public_key,
		},
		verify_key: VerifyKeyFormatInt {
			key_id: server_output.keypair_sign_id.clone(),
			key: verify_key,
		},
		exported_public_key,
		exported_verify_key,
	})
}

/**
Make the prepare and done login req.

- prep login to get the salt
- done login to get the encrypted master key, because this key is never stored on the device
*/
fn change_password_internally(old_pw: &str, new_pw: &str, server_output_prep_login: &str, server_output_done_login: &str)
	-> Result<String, SdkError>
{
	let server_output_prep_login: PrepareLoginSaltServerOutput = handle_server_response(server_output_prep_login)?;
	let server_output_done_login: DoneLoginServerKeysOutput = handle_server_response(server_output_done_login)?;

	let encrypted_master_key =
		Base64::decode_vec(server_output_done_login.encrypted_master_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;
	let old_salt = Base64::decode_vec(server_output_prep_login.salt_string.as_str()).map_err(|_| SdkError::DecodeSaltFailed)?;

	let output = core_user::change_password(
		old_pw,
		new_pw,
		&old_salt,
		&encrypted_master_key,
		server_output_prep_login.derived_encryption_key_alg.as_str(),
	)?;

	//prepare for the server
	let new_encrypted_master_key = Base64::encode_string(&output.master_key_info.encrypted_master_key);

	let new_client_random_value = client_random_value_to_string(&output.client_random_value);

	//the 16 bytes of the org. hashed key
	let new_hashed_authentication_key = hashed_authentication_key_to_string(&output.hashed_authentication_key_bytes);

	let old_auth_key = derive_auth_key_for_auth_to_string(&output.old_auth_key);

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
		.map_err(|_| SdkError::JsonToStringFailed)?)
}

fn reset_password_internally(
	new_password: &str,
	decrypted_private_key: &PrivateKeyFormatInt,
	decrypted_sign_key: &SignKeyFormatInt,
) -> Result<String, SdkError>
{
	let out = core_user::password_reset(new_password, &decrypted_private_key.key, &decrypted_sign_key.key)?;

	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//prepare for the server
	let client_random_value = client_random_value_to_string(&out.client_random_value);
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

	let master_key = MasterKey {
		encrypted_master_key,
		master_key_alg: out.master_key_alg.to_string(),
		encrypted_master_key_alg: out.master_key_info.alg.to_string(),
	};

	let data = ResetPasswordData {
		client_random_value,
		hashed_authentication_key,
		master_key,
		derived_alg: out.derived_alg.to_string(),
		encrypted_sign_key,
		encrypted_private_key,
	};

	Ok(data.to_string().map_err(|_| SdkError::JsonToStringFailed)?)
}

/**
# Prepare update user keys

When changing the user keys so the user can update the old content which was encrypted by the old user keys.

After this step the user got access to all old user keys and
can start decrypting the content with the old keys and encrypt it with the new keys.

This function is used when the user don't new encrypt all content as once but split it around days.
When the user will start new encrypt the next chunks, this function is needed to get the old key too
(because for login we only use the actual keys).

Password change or reset is not possible during the key update.
*/
fn prepare_update_user_keys_internally(password: &str, server_output: &MultipleLoginServerOutput) -> Result<Vec<KeyDataInt>, SdkError>
{
	let mut encrypted_output = Vec::with_capacity(server_output.logins.len());

	//decrypt all keys via the password, so the sdk can start to decrypt the content with the old keys and encrypt with the new

	let mut i = 0;

	for out in &server_output.logins {
		//get the derived key from the password
		//creat the salt in the client for the old keys. it is ok because the user is already auth
		let salt = generate_salt_from_base64(
			out.client_random_value.as_str(),
			out.derived_encryption_key_alg.as_str(),
			"",
		)?;

		let result = core_user::prepare_login(password, &salt, out.derived_encryption_key_alg.as_str())?;
		let derived_key = result.master_key_encryption_key;

		//now done login
		//should everytime the same len
		let done_login_server_output = match server_output.done_logins.get(i) {
			Some(v) => v,
			None => return Err(SdkError::KeyDecryptFailed),
		};

		let done_login = done_login_internally_with_server_out(&derived_key, done_login_server_output)?;
		encrypted_output.push(done_login);

		i += 1;
	}

	Ok(encrypted_output)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::string::ToString;

	use sentc_crypto_common::user::{KeyDerivedData, RegisterData};
	use sentc_crypto_common::ServerOutput;

	use super::*;
	use crate::util::server::generate_salt_from_base64_to_string;
	use crate::util::KeyData;

	pub(crate) fn simulate_server_prepare_login(derived: &KeyDerivedData) -> String
	{
		//and now try to login
		//normally the salt gets calc by the api
		let salt_string = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "").unwrap();

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

	pub(crate) fn simulate_server_done_login(data: RegisterData) -> String
	{
		let RegisterData {
			derived,
			master_key,
			..
		} = data;

		//get the server output back
		let out = DoneLoginServerKeysOutput {
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
			result: Some(out),
		}
		.to_string()
		.unwrap()
	}

	#[cfg(feature = "rust")]
	pub(crate) fn create_user() -> KeyData
	{
		let username = "admin";
		let password = "12345";

		let out_string = register(username, password).unwrap();

		let out = RegisterData::from_string(out_string.as_str()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		#[cfg(feature = "rust")]
		let (_, master_key_encryption_key) = prepare_login(username, password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		#[cfg(feature = "rust")]
		let done_login = done_login(&master_key_encryption_key, &server_output).unwrap();

		#[cfg(feature = "rust")]
		done_login
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_user() -> KeyData
	{
		let username = "admin";
		let password = "12345";

		let out_string = register(username, password).unwrap();

		let out = RegisterData::from_string(out_string.as_str()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		#[cfg(not(feature = "rust"))]
		let (_auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		#[cfg(not(feature = "rust"))]
		let done_login = done_login(master_key_encryption_key.as_str(), server_output.as_str()).unwrap();

		#[cfg(not(feature = "rust"))]
		done_login
	}
}
