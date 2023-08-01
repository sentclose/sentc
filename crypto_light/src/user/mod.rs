#[cfg(not(feature = "rust"))]
#[allow(clippy::module_inception)]
mod user;
#[cfg(feature = "rust")]
mod user_rust;

use alloc::string::{String, ToString};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use sentc_crypto_common::group::GroupNewMemberLightInput;
use sentc_crypto_common::user::{
	DoneLoginServerOutput,
	DoneLoginServerReturn,
	JwtRefreshInput,
	KeyDerivedData,
	MasterKey,
	RegisterServerOutput,
	UserDeviceDoneRegisterInputLight,
	UserDeviceRegisterInput,
	UserDeviceRegisterOutput,
	UserIdentifierAvailableServerInput,
	UserIdentifierAvailableServerOutput,
	UserUpdateServerInput,
	VerifyLoginLightOutput,
};
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_core::DeriveMasterKeyForAuth;
use sentc_crypto_utils::user::UserPreVerifyLogin;
use sentc_crypto_utils::{
	client_random_value_to_string,
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	handle_server_response,
	hashed_authentication_key_to_string,
};

#[cfg(not(feature = "rust"))]
pub use self::user::{
	done_check_user_identifier_available,
	done_register,
	done_register_device_start,
	done_validate_mfa,
	generate_user_register_data,
	prepare_check_user_identifier_available,
	prepare_login_start,
	prepare_refresh_jwt,
	prepare_register_device,
	prepare_user_identifier_update,
	register,
	register_typed,
	verify_login,
};
#[cfg(feature = "rust")]
pub use self::user_rust::{
	done_check_user_identifier_available,
	done_register,
	done_register_device_start,
	done_validate_mfa,
	generate_user_register_data,
	prepare_check_user_identifier_available,
	prepare_login_start,
	prepare_refresh_jwt,
	prepare_register_device,
	prepare_user_identifier_update,
	register,
	register_typed,
	verify_login,
};
use crate::error::SdkLightError;
use crate::{DeviceKeyDataInt, UserDataInt};

fn generate_user_register_data_internally() -> Result<(String, String), SdkLightError>
{
	let (identifier, password) = sentc_crypto_core::generate_user_register_data()?;

	let encoded_identifier = Base64UrlUnpadded::encode_string(&identifier);
	let encoded_password = Base64UrlUnpadded::encode_string(&password);

	Ok((encoded_identifier, encoded_password))
}

fn prepare_check_user_identifier_available_internally(user_identifier: &str) -> Result<String, SdkLightError>
{
	UserIdentifierAvailableServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn done_check_user_identifier_available_internally(server_output: &str) -> Result<bool, SdkLightError>
{
	let server_output: UserIdentifierAvailableServerOutput = handle_server_response(server_output)?;

	Ok(server_output.available)
}

fn register_internally(user_identifier: &str, password: &str) -> Result<String, SdkLightError>
{
	//use this also for device register because user and device register are the same in the light version in the client.
	//use this also for reset password data
	let out = prepare_register_device_private_internally(user_identifier, password)?;

	serde_json::to_string(&out).map_err(|_| SdkLightError::JsonToStringFailed)
}

fn done_register_internally(server_output: &str) -> Result<UserId, SdkLightError>
{
	let out: RegisterServerOutput = handle_server_response(server_output)?;

	Ok(out.user_id)
}

fn done_register_device_start_internally(server_output: &str) -> Result<(), SdkLightError>
{
	let _out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

	Ok(())
}

/**
Prepare the user group keys for the new device.

Call this fn from the active device with the server output from register device

Return the public key of the device, for the key session
 */
fn prepare_register_device_internally(server_output: &str) -> Result<String, SdkLightError>
{
	let out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

	serde_json::to_string(&UserDeviceDoneRegisterInputLight {
		user_group: GroupNewMemberLightInput {
			rank: None,
		},
		token: out.token,
	})
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn prepare_register_device_private_internally(device_identifier: &str, password: &str) -> Result<UserDeviceRegisterInput, SdkLightError>
{
	let out = sentc_crypto_core::user::register(password)?;

	//encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//export the public keys (decrypt and verify) to a key format
	let public_key = export_raw_public_key_to_pem(&out.public_key)?;
	let verify_key = export_raw_verify_key_to_pem(&out.verify_key)?;

	//export the random value
	let client_random_value = client_random_value_to_string(&out.client_random_value);
	//export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

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

	Ok(UserDeviceRegisterInput {
		master_key,
		derived,
		device_identifier: device_identifier.to_string(),
	})
}

//__________________________________________________________________________________________________
//login

/**
# prepare the data for the server req
 */
fn prepare_login_start_internally(user_identifier: &str) -> Result<String, SdkLightError>
{
	Ok(sentc_crypto_utils::user::prepare_login_start(user_identifier)?)
}

/**
# Starts the login process

1. Get the auth key and the master key encryption key from the password.
2. Send the auth key to the server to get the DoneLoginInput back
 */
pub fn prepare_login(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, String, DeriveMasterKeyForAuth), SdkLightError>
{
	Ok(sentc_crypto_utils::user::prepare_login(
		user_identifier,
		password,
		server_output,
	)?)
}

pub fn check_done_login(server_output: &str) -> Result<DoneLoginServerReturn, SdkLightError>
{
	Ok(sentc_crypto_utils::user::check_done_login(server_output)?)
}

pub fn prepare_validate_mfa(auth_key: String, device_identifier: String, token: String) -> Result<String, SdkLightError>
{
	Ok(sentc_crypto_utils::user::prepare_validate_mfa(
		auth_key,
		device_identifier,
		token,
	)?)
}

fn done_validate_mfa_internally(
	master_key_encryption: &DeriveMasterKeyForAuth,
	auth_key: String,
	device_identifier: String,
	server_output: &str,
) -> Result<UserPreVerifyLogin, SdkLightError>
{
	Ok(sentc_crypto_utils::user::done_validate_mfa(
		master_key_encryption,
		auth_key,
		device_identifier,
		server_output,
	)?)
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private key, in pem exported public key
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public key to the internal format
 */
pub fn done_login(
	master_key_encryption: &DeriveMasterKeyForAuth,
	auth_key: String,
	device_identifier: String,
	server_output: DoneLoginServerOutput,
) -> Result<UserPreVerifyLogin, SdkLightError>
{
	Ok(sentc_crypto_utils::user::done_login(
		master_key_encryption,
		auth_key,
		device_identifier,
		server_output,
	)?)
}

fn verify_login_internally(
	server_output: &str,
	user_id: UserId,
	device_id: DeviceId,
	device_keys: DeviceKeyDataInt,
) -> Result<UserDataInt, SdkLightError>
{
	let server_output: VerifyLoginLightOutput = handle_server_response(server_output)?;

	Ok(UserDataInt {
		device_keys,
		jwt: server_output.jwt,
		refresh_token: server_output.refresh_token,
		user_id,
		device_id,
	})
}

//__________________________________________________________________________________________________

fn prepare_user_identifier_update_internally(user_identifier: String) -> Result<String, SdkLightError>
{
	let input = UserUpdateServerInput {
		user_identifier,
	};

	input
		.to_string()
		.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn prepare_refresh_jwt_internally(refresh_token: String) -> Result<String, SdkLightError>
{
	JwtRefreshInput {
		refresh_token,
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

//__________________________________________________________________________________________________

pub fn change_password(
	old_pw: &str,
	new_pw: &str,
	server_output_prep_login: &str,
	server_output_done_login: DoneLoginServerOutput,
) -> Result<String, SdkLightError>
{
	Ok(sentc_crypto_utils::user::change_password(
		old_pw,
		new_pw,
		server_output_prep_login,
		server_output_done_login,
	)?)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::vec::Vec;

	use sentc_crypto_common::user::{DoneLoginServerKeysOutput, DoneLoginServerOutput, PrepareLoginSaltServerOutput, VerifyLoginInput};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::generate_salt;
	use sentc_crypto_utils::{client_random_value_from_string, import_public_key_from_pem_with_alg};

	use super::*;

	fn encrypt_login_verify_challenge(public_key_in_pem: &str, public_key_alg: &str, challenge: &str) -> Result<String, SdkLightError>
	{
		let public_key = import_public_key_from_pem_with_alg(public_key_in_pem, public_key_alg)?;

		let encrypted_eph_key = sentc_crypto_core::crypto::encrypt_asymmetric(&public_key, challenge.as_bytes())?;

		Ok(Base64::encode_string(&encrypted_eph_key))
	}

	fn generate_salt_from_base64(client_random_value: &str, alg: &str, add_str: &str) -> Vec<u8>
	{
		let client_random_value = client_random_value_from_string(client_random_value, alg).unwrap();

		generate_salt(client_random_value, add_str)
	}

	fn generate_salt_from_base64_to_string(client_random_value: &str, alg: &str, add_str: &str) -> String
	{
		let salt = generate_salt_from_base64(client_random_value, alg, add_str);

		Base64::encode_string(&salt)
	}

	pub(crate) fn simulate_server_prepare_login(derived: &KeyDerivedData) -> String
	{
		let salt_string = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "");

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

	pub(crate) fn simulate_server_done_login(device: UserDeviceRegisterInput) -> DoneLoginServerOutput
	{
		let challenge = encrypt_login_verify_challenge(
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

	pub(crate) fn simulate_verify_login(challenge: &str) -> String
	{
		let challenge: VerifyLoginInput = serde_json::from_str(challenge).unwrap();
		assert_eq!(challenge.challenge, "abcd");

		let out = VerifyLoginLightOutput {
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
}
