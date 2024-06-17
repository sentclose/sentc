use alloc::string::{String, ToString};

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{
	ChangePasswordData,
	DoneLoginServerInput,
	DoneLoginServerKeysOutput,
	DoneLoginServerOutput,
	DoneLoginServerReturn,
	JwtRefreshInput,
	OtpInput,
	PrepareLoginSaltServerOutput,
	PrepareLoginServerInput,
	UserPublicKeyData,
	UserUpdateServerInput,
	UserVerifyKeyData,
	VerifyLoginInput,
};
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_core::cryptomat::{DeriveMasterKeyForAuth, PwHash, Sk};
use serde::{Deserialize, Serialize};

use crate::cryptomat::{PkWrapper, SignComposerWrapper, SignKWrapper, SkWrapper, StaticKeyComposerWrapper, VerifyKWrapper};
use crate::error::SdkUtilError;
use crate::{client_random_value_to_string, derive_auth_key_for_auth_to_string, handle_server_response, hashed_authentication_key_to_string};

/**
# key storage structure for the rust feature

It can be used with other rust programs.

The different to the internally DoneLoginOutput ist that,
the KeyFormat is sued for each where, were the key id is saved too
 */
pub struct DeviceKeyDataInt<Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper>
{
	pub private_key: Sk,
	pub sign_key: SiK,
	pub public_key: Pk,
	pub verify_key: Vk,
	pub exported_public_key: UserPublicKeyData,
	pub exported_verify_key: UserVerifyKeyData,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceKeyDataExport
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl<Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper> TryFrom<DeviceKeyDataInt<Sk, Pk, SiK, Vk>> for DeviceKeyDataExport
{
	type Error = SdkUtilError;

	fn try_from(value: DeviceKeyDataInt<Sk, Pk, SiK, Vk>) -> Result<Self, Self::Error>
	{
		Ok(Self {
			private_key: value.private_key.to_string()?,
			public_key: value.public_key.to_string()?,
			sign_key: value.sign_key.to_string()?,
			verify_key: value.verify_key.to_string()?,
			exported_public_key: value
				.exported_public_key
				.to_string()
				.map_err(|_e| SdkUtilError::JsonToStringFailed)?,
			exported_verify_key: value
				.exported_verify_key
				.to_string()
				.map_err(|_e| SdkUtilError::JsonToStringFailed)?,
		})
	}
}

pub struct UserPreVerifyLogin<Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper>
{
	pub challenge: String,
	pub device_keys: DeviceKeyDataInt<Sk, Pk, SiK, Vk>,
	pub user_id: UserId,
	pub device_id: DeviceId,
}

fn decrypt_login_challenge(private_key: &impl SkWrapper, challenge: &str) -> Result<String, SdkUtilError>
{
	//moved to util crate because this must be done for light and normal sdk

	let challenge = Base64::decode_vec(challenge).map_err(|_| SdkUtilError::DecryptingLoginChallengeFailed)?;

	let decrypted = private_key.get_key().decrypt(&challenge)?;

	String::from_utf8(decrypted).map_err(|_| SdkUtilError::DecryptingLoginChallengeFailed)
}

/**
# prepare the data for the server req

 */
pub fn prepare_login_start(user_identifier: &str) -> Result<String, SdkUtilError>
{
	PrepareLoginServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkUtilError::JsonToStringFailed)
}

/**
# Starts the login process

1. Get the auth key and the master key encryption key from the password.
2. Send the auth key to the server to get the DoneLoginInput back
 */
pub fn prepare_login<H: PwHash>(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, String, H::DMK), SdkUtilError>
{
	let server_output: PrepareLoginSaltServerOutput = handle_server_response(server_output)?;

	let salt = Base64::decode_vec(server_output.salt_string.as_str()).map_err(|_| SdkUtilError::DecodeSaltFailed)?;
	let result = sentc_crypto_core::user::prepare_login::<H>(password, &salt, server_output.derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = derive_auth_key_for_auth_to_string(&result.auth_key);

	let input = DoneLoginServerInput {
		auth_key: auth_key.clone(),
		device_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkUtilError::JsonToStringFailed)?;

	Ok((input, auth_key, result.master_key_encryption_key))
}

pub fn check_done_login(server_output: &str) -> Result<DoneLoginServerReturn, SdkUtilError>
{
	let server_output: DoneLoginServerReturn = handle_server_response(server_output)?;

	Ok(server_output)
}

/**
If user enabled mfa then prepare the input here. the token is from the mfa auth like totp, or from the recover keys
*/
pub fn prepare_validate_mfa(auth_key: String, device_identifier: String, token: String) -> Result<String, SdkUtilError>
{
	serde_json::to_string(&OtpInput {
		token,
		auth_key,
		device_identifier,
	})
	.map_err(|_| SdkUtilError::JsonToStringFailed)
}

/**
If the user enables mfa, do the done login here
*/
pub fn done_validate_mfa<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper>(
	master_key_encryption: &impl DeriveMasterKeyForAuth,
	auth_key: String,
	device_identifier: String,
	server_output: &str,
) -> Result<
	UserPreVerifyLogin<
		<SkC as StaticKeyComposerWrapper>::SkWrapper,
		<SkC as StaticKeyComposerWrapper>::PkWrapper,
		<SiKC as SignComposerWrapper>::SignKWrapper,
		<SiKC as SignComposerWrapper>::VerifyKWrapper,
	>,
	SdkUtilError,
>
{
	let server_output: DoneLoginServerOutput = handle_server_response(server_output)?;

	done_login::<SkC, SiKC>(master_key_encryption, auth_key, device_identifier, server_output)
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private and sign keys, in pem exported public and verify keys
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public and verify keys to the internal format
 */
pub fn done_login<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper>(
	master_key_encryption: &impl DeriveMasterKeyForAuth,
	auth_key: String,
	device_identifier: String,
	server_output: DoneLoginServerOutput,
) -> Result<
	UserPreVerifyLogin<
		<SkC as StaticKeyComposerWrapper>::SkWrapper,
		<SkC as StaticKeyComposerWrapper>::PkWrapper,
		<SiKC as SignComposerWrapper>::SignKWrapper,
		<SiKC as SignComposerWrapper>::VerifyKWrapper,
	>,
	SdkUtilError,
>
{
	let device_data = server_output.device_keys;

	let device_keys = done_login_internally_with_device_out::<SkC, SiKC>(master_key_encryption, &device_data)?;

	let challenge = decrypt_login_challenge(&device_keys.private_key, &server_output.challenge)?;

	Ok(UserPreVerifyLogin {
		device_keys,
		challenge: serde_json::to_string(&VerifyLoginInput {
			auth_key,
			device_identifier,
			challenge,
		})
		.map_err(|_e| SdkUtilError::JsonToStringFailed)?,
		user_id: device_data.user_id,
		device_id: device_data.device_id,
	})
}

fn done_login_internally_with_device_out<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper>(
	master_key_encryption: &impl DeriveMasterKeyForAuth,
	server_output: &DoneLoginServerKeysOutput,
) -> Result<
	DeviceKeyDataInt<
		<SkC as StaticKeyComposerWrapper>::SkWrapper,
		<SkC as StaticKeyComposerWrapper>::PkWrapper,
		<SiKC as SignComposerWrapper>::SignKWrapper,
		<SiKC as SignComposerWrapper>::VerifyKWrapper,
	>,
	SdkUtilError,
>
{
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_master_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = Base64::decode_vec(server_output.encrypted_sign_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let out = sentc_crypto_core::user::done_login::<SkC::Composer, SiKC::Composer>(
		master_key_encryption,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.keypair_encrypt_alg.as_str(),
		&encrypted_sign_key,
		server_output.keypair_sign_alg.as_str(),
	)?;

	//now prepare the public and verify key for use
	let public_key = SkC::pk_from_pem(
		&server_output.public_key_string,
		&server_output.keypair_encrypt_alg,
		server_output.keypair_encrypt_id.clone(),
	)?;

	let verify_key = SiKC::vk_from_pem(
		&server_output.verify_key_string,
		&server_output.keypair_sign_alg,
		server_output.keypair_sign_id.clone(),
	)?;

	let private_key = SkC::sk_from_inner(out.private_key, server_output.keypair_encrypt_id.clone());

	let sign_key = SiKC::sk_from_inner(out.sign_key, server_output.keypair_sign_id.clone());

	//export this too, so the user can verify the own data
	let exported_public_key = UserPublicKeyData {
		public_key_pem: server_output.public_key_string.to_string(),
		public_key_alg: server_output.keypair_encrypt_alg.to_string(),
		public_key_id: server_output.keypair_encrypt_id.clone(),
		public_key_sig: None, //no sig for device keys
		public_key_sig_key_id: None,
	};

	let exported_verify_key = UserVerifyKeyData {
		verify_key_pem: server_output.verify_key_string.to_string(),
		verify_key_alg: server_output.keypair_sign_alg.to_string(),
		verify_key_id: server_output.keypair_sign_id.clone(),
	};

	Ok(DeviceKeyDataInt {
		private_key,
		sign_key,
		public_key,
		verify_key,
		exported_public_key,
		exported_verify_key,
	})
}

/**
Make the prepare and done login req.

- prep login to get the salt
- done login to get the encrypted master key, because this key is never stored on the device
 */
pub fn change_password<H: PwHash>(
	old_pw: &str,
	new_pw: &str,
	server_output_prep_login: &str,
	server_output_done_login: DoneLoginServerOutput,
) -> Result<String, SdkUtilError>
{
	let server_output_prep_login: PrepareLoginSaltServerOutput = handle_server_response(server_output_prep_login)?;

	let encrypted_master_key = Base64::decode_vec(
		server_output_done_login
			.device_keys
			.encrypted_master_key
			.as_str(),
	)
	.map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let old_salt = Base64::decode_vec(server_output_prep_login.salt_string.as_str()).map_err(|_| SdkUtilError::DecodeSaltFailed)?;

	let output = sentc_crypto_core::user::change_password::<H>(
		old_pw,
		new_pw,
		&old_salt,
		&encrypted_master_key,
		server_output_prep_login.derived_encryption_key_alg.as_str(),
	)?;

	//prepare for the server
	let new_encrypted_master_key = Base64::encode_string(&output.encrypted_master_key);

	let new_client_random_value = client_random_value_to_string(&output.client_random_value);

	//the 16 bytes of the org. hashed key
	let new_hashed_authentication_key = hashed_authentication_key_to_string(&output.hashed_authentication_key_bytes);

	let old_auth_key = derive_auth_key_for_auth_to_string(&output.old_auth_key);

	let pw_change_out = ChangePasswordData {
		new_derived_alg: output.derived_alg.to_string(),
		new_encrypted_master_key,
		new_client_random_value,
		new_hashed_authentication_key,
		new_encrypted_master_key_alg: output.encrypted_master_key_alg.to_string(),
		old_auth_key,
	};

	pw_change_out
		.to_string()
		.map_err(|_| SdkUtilError::JsonToStringFailed)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, SdkUtilError>
{
	JwtRefreshInput {
		refresh_token,
	}
	.to_string()
	.map_err(|_| SdkUtilError::JsonToStringFailed)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, SdkUtilError>
{
	let input = UserUpdateServerInput {
		user_identifier,
	};

	input
		.to_string()
		.map_err(|_| SdkUtilError::JsonToStringFailed)
}
