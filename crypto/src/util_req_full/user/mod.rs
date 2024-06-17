#[cfg(feature = "export")]
mod user_export;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use sentc_crypto_common::user::{OtpRecoveryKeysOutput, OtpRegister, UserDeviceList, UserInitServerOutput, UserPublicKeyData};
use sentc_crypto_core::cryptomat::{DeriveMasterKeyForAuth, PwHash, SearchableKeyGen, SortableKeyGen};
use sentc_crypto_utils::cryptomat::{
	PkFromUserKeyWrapper,
	PkWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKWrapper,
	SignKeyPairWrapper,
	SkWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
	VerifyKWrapper,
};
use sentc_crypto_utils::http::{auth_req, non_auth_req, HttpMethod};
use sentc_crypto_utils::user::UserPreVerifyLogin;
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};
#[cfg(feature = "export")]
pub use user_export::*;

use crate::entities::user::{UserDataInt, UserKeyDataInt};
use crate::group::Group;
use crate::user::User;
use crate::util_req_full::SessionKind;
use crate::{SdkError, StdUser};

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOut<S: SymKeyWrapper, Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper, DMK: DeriveMasterKeyForAuth>
{
	Direct(UserDataInt<S, Sk, Pk, SiK, Vk>),
	Otp(sentc_crypto_utils::full::user::PrepareLoginOtpOutput<DMK>),
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
where
	SGen: SymKeyGenWrapper,
	StGen: StaticKeyPairWrapper,
	SignGen: SignKeyPairWrapper,
	SearchGen: SearchableKeyGen,
	SortGen: SortableKeyGen,
	SC: SymKeyComposerWrapper,
	StC: StaticKeyComposerWrapper,
	SignC: SignComposerWrapper,
	SearchC: SearchableKeyComposerWrapper,
	SortC: SortableKeyComposerWrapper,
	PC: PkFromUserKeyWrapper,
	VC: VerifyKFromUserKeyWrapper,
	PwH: PwHash,
{
	pub async fn register_req(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<String, SdkError>
	{
		let register_input = Self::register(user_identifier, password)?;

		let url = base_url + "/api/v1/register";

		let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(register_input)).await?;

		let out = crate::user::user::done_register(&res)?;

		Ok(out)
	}

	pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Result<String, SdkError>
	{
		let url = base_url + "/api/v1/user/prepare_register_device";

		let input = Self::prepare_register_device_start(device_identifier, password)?;

		let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(input)).await?;

		//check the server output
		crate::user::user::done_register_device_start(&res)?;

		Ok(res)
	}

	pub async fn register_device(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		server_output: &str,
		key_count: i32,
		user_keys: &[&impl SymKeyWrapper],
	) -> Result<(Option<String>, UserPublicKeyData), SdkError>
	{
		let url = base_url + "/api/v1/user/done_register_device";

		let key_session = key_count > 50;

		let (input, exported_device_public_key) = StdUser::prepare_register_device(server_output, user_keys, key_session)?;

		let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(input), jwt).await?;

		let out: sentc_crypto_common::group::GroupAcceptJoinReqServerOutput = handle_server_response(&res)?;

		Ok((out.session_id, exported_device_public_key))
	}

	pub async fn device_key_session(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		session_id: &str,
		user_public_key: &UserPublicKeyData,
		user_keys: &[&impl SymKeyWrapper],
	) -> Result<(), SdkError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::insert_session_keys(
			base_url,
			auth_token,
			jwt,
			"",
			SessionKind::UserGroup,
			session_id,
			user_public_key,
			user_keys,
			None,
		)
		.await
	}

	//______________________________________________________________________________________________
	//Login

	async fn verify_login_int(
		base_url: String,
		auth_token: &str,
		pre_verify: UserPreVerifyLogin<StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
	) -> Result<UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let url = base_url + "/api/v1/verify_login";
		let server_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(pre_verify.challenge)).await?;

		let keys = Self::verify_login(
			&server_out,
			pre_verify.user_id,
			pre_verify.device_id,
			pre_verify.device_keys,
		)?;

		Ok(keys)
	}

	pub async fn login(
		base_url: String,
		auth_token: &str,
		user_identifier: &str,
		password: &str,
	) -> Result<PreLoginOut<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper, PwH::DMK>, SdkError>
	{
		let pre_login = sentc_crypto_utils::full::user::login::<StC, SignC, PwH>(base_url.clone(), auth_token, user_identifier, password).await?;

		match pre_login {
			sentc_crypto_utils::full::user::PreLoginOut::Direct(d) => {
				let out = Self::verify_login_int(base_url, auth_token, d).await?;

				Ok(PreLoginOut::Direct(out))
			},
			sentc_crypto_utils::full::user::PreLoginOut::Otp(d) => {
				//Otp means the user enables otp, so use done_otp_login fn with the user token before verify,
				// DoneLoginServerOutput is not returned at this point

				//export the data needed for this fn

				Ok(PreLoginOut::Otp(
					sentc_crypto_utils::full::user::PrepareLoginOtpOutput {
						master_key: d.master_key,
						auth_key: d.auth_key,
					},
				))
			},
		}
	}

	pub async fn mfa_login(
		base_url: String,
		auth_token: &str,
		master_key_encryption: &impl DeriveMasterKeyForAuth,
		auth_key: String,
		user_identifier: String,
		token: String,
		recovery: bool,
	) -> Result<UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let keys = sentc_crypto_utils::full::user::mfa_login::<StC, SignC>(
			base_url.clone(),
			auth_token,
			master_key_encryption,
			auth_key,
			user_identifier,
			token,
			recovery,
		)
		.await?;

		Self::verify_login_int(base_url, auth_token, keys).await
	}

	pub async fn fetch_user_key(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		key_id: &str,
		private_key: &impl SkWrapper,
	) -> Result<UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let url = base_url + "/api/v1/user/user_keys/key/" + key_id;

		let server_out = auth_req(HttpMethod::GET, &url, auth_token, None, jwt).await?;

		let keys = Self::done_key_fetch(private_key, &server_out)?;

		Ok(keys)
	}

	pub async fn get_fresh_jwt(
		base_url: String,
		auth_token: &str,
		user_identifier: &str,
		password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<String, SdkError>
	{
		let (_, keys, _) = sentc_crypto_utils::full::user::prepare_user_fresh_jwt::<StC, SignC, PwH>(
			base_url.clone(),
			auth_token,
			user_identifier,
			password,
			mfa_token,
			mfa_recovery,
		)
		.await?;

		let keys = Self::verify_login_int(base_url, auth_token, keys).await?;

		Ok(keys.jwt)
	}

	//______________________________________________________________________________________________

	pub async fn change_password_req(
		base_url: String,
		auth_token: &str,
		user_identifier: &str,
		old_password: &str,
		new_password: &str,
		mfa_token: Option<String>,
		mfa_recovery: Option<bool>,
	) -> Result<(), SdkError>
	{
		let (prep_login_out, keys, done_login_out) = sentc_crypto_utils::full::user::prepare_user_fresh_jwt::<StC, SignC, PwH>(
			base_url.clone(),
			auth_token,
			user_identifier,
			old_password,
			mfa_token,
			mfa_recovery,
		)
		.await?;

		let keys = Self::verify_login_int(base_url.clone(), auth_token, keys).await?;

		Ok(sentc_crypto_utils::full::user::done_change_password::<PwH>(
			base_url,
			auth_token,
			old_password,
			new_password,
			&keys.jwt,
			&prep_login_out,
			done_login_out,
		)
		.await?)
	}

	pub async fn reset_password_req(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		new_password: &str,
		decrypted_private_key: &impl SkWrapper,
		decrypted_sign_key: &impl SignKWrapper,
	) -> Result<(), SdkError>
	{
		let url = base_url + "/api/v1/user/reset_pw";

		let input = Self::reset_password(new_password, decrypted_private_key, decrypted_sign_key)?;

		let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(input), jwt).await?;

		Ok(handle_general_server_response(&res)?)
	}

	//______________________________________________________________________________________________

	pub async fn key_rotation(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		device_public_key: &impl PkWrapper,
		pre_user_key: &impl SymKeyWrapper,
	) -> Result<String, SdkError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::key_rotation_req(
			base_url,
			auth_token,
			jwt,
			"",
			device_public_key,
			pre_user_key,
			true,
			None::<&SignC::SignKWrapper>,
			Default::default(),
			None,
		)
		.await
	}

	pub async fn done_key_rotation(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		server_output: sentc_crypto_common::group::KeyRotationInput,
		pre_user_key: &impl SymKeyWrapper,
		device_public_key: &impl PkWrapper,
		device_private_key: &impl SkWrapper,
	) -> Result<(), SdkError>
	{
		Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::done_key_rotation_req(
			base_url,
			auth_token,
			jwt,
			"",
			server_output,
			pre_user_key,
			device_public_key,
			device_private_key,
			true,
			Default::default(),
			None,
		)
		.await
	}
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type BoolRes = Result<bool, String>;
#[cfg(not(feature = "export"))]
type BoolRes = Result<bool, SdkError>;

pub async fn check_user_identifier_available(base_url: String, auth_token: &str, user_identifier: &str) -> BoolRes
{
	let server_input = crate::user::user::prepare_check_user_identifier_available(user_identifier)?;

	let url = base_url + "/api/v1/exists";

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(server_input)).await?;
	let out = crate::user::user::done_check_user_identifier_available(res.as_str())?;

	Ok(out)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type Res = Result<String, String>;
#[cfg(not(feature = "export"))]
type Res = Result<String, SdkError>;

#[cfg(feature = "export")]
type InitRes = Result<UserInitServerOutput, String>;
#[cfg(not(feature = "export"))]
type InitRes = Result<UserInitServerOutput, SdkError>;

#[cfg(feature = "export")]
type DeviceListRes = Result<Vec<UserDeviceList>, String>;
#[cfg(not(feature = "export"))]
type DeviceListRes = Result<Vec<UserDeviceList>, SdkError>;

pub async fn refresh_jwt(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Res
{
	Ok(sentc_crypto_utils::full::user::refresh_jwt(base_url, auth_token, jwt, refresh_token).await?)
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> InitRes
{
	Ok(sentc_crypto_utils::full::user::init_user(base_url, auth_token, jwt, refresh_token).await?)
}

pub async fn get_user_devices(base_url: String, auth_token: &str, jwt: &str, last_fetched_time: &str, last_fetched_id: &str) -> DeviceListRes
{
	Ok(sentc_crypto_utils::full::user::get_user_devices(base_url, auth_token, jwt, last_fetched_time, last_fetched_id).await?)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type VoidRes = Result<(), String>;

#[cfg(not(feature = "export"))]
type VoidRes = Result<(), SdkError>;

pub async fn delete(base_url: String, auth_token: &str, fresh_jwt: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::done_delete(base_url, auth_token, fresh_jwt).await?)
}

/**
# Remove a device from the user group.

This can only be done when the actual device got a fresh jwt,
to make sure that no hacker can remove devices.
 */
pub async fn delete_device(base_url: String, auth_token: &str, fresh_jwt: &str, device_id: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::done_delete_device(base_url, auth_token, fresh_jwt, device_id).await?)
}

//__________________________________________________________________________________________________

pub async fn update(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::update(base_url, auth_token, jwt, user_identifier).await?)
}

//__________________________________________________________________________________________________
//Otp
#[cfg(feature = "export")]
type RegisterRawOtpRes = Result<OtpRegister, String>;
#[cfg(not(feature = "export"))]
type RegisterRawOtpRes = Result<OtpRegister, SdkError>;

#[cfg(feature = "export")]
type RegisterOtpRes = Result<(String, Vec<String>), String>;
#[cfg(not(feature = "export"))]
type RegisterOtpRes = Result<(String, Vec<String>), SdkError>;

#[cfg(feature = "export")]
type OtpRecoveryKeyRes = Result<OtpRecoveryKeysOutput, String>;
#[cfg(not(feature = "export"))]
type OtpRecoveryKeyRes = Result<OtpRecoveryKeysOutput, SdkError>;

pub async fn register_raw_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> RegisterRawOtpRes
{
	Ok(sentc_crypto_utils::full::user::register_raw_otp(base_url, auth_token, fresh_jwt).await?)
}

pub async fn register_otp(base_url: String, auth_token: &str, issuer: &str, audience: &str, fresh_jwt: &str) -> RegisterOtpRes
{
	Ok(sentc_crypto_utils::full::user::register_otp(base_url, auth_token, fresh_jwt, issuer, audience).await?)
}

pub async fn get_otp_recover_keys(base_url: String, auth_token: &str, fresh_jwt: &str) -> OtpRecoveryKeyRes
{
	Ok(sentc_crypto_utils::full::user::get_otp_recover_keys(base_url, auth_token, fresh_jwt).await?)
}

pub async fn reset_raw_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> RegisterRawOtpRes
{
	Ok(sentc_crypto_utils::full::user::reset_raw_otp(base_url, auth_token, fresh_jwt).await?)
}

pub async fn reset_otp(base_url: String, auth_token: &str, issuer: &str, audience: &str, fresh_jwt: &str) -> RegisterOtpRes
{
	Ok(sentc_crypto_utils::full::user::reset_otp(base_url, auth_token, fresh_jwt, issuer, audience).await?)
}

pub async fn disable_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::disable_otp(base_url, auth_token, fresh_jwt).await?)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type UserPublicKeyRes = Result<
	(
		String,
		sentc_crypto_common::EncryptionKeyPairId,
		Option<sentc_crypto_common::SignKeyPairId>,
	),
	String,
>;
#[cfg(not(feature = "export"))]
type UserPublicKeyRes = Result<UserPublicKeyData, SdkError>;

#[cfg(feature = "export")]
type UserVerifyKeyRes = Result<String, String>;
#[cfg(not(feature = "export"))]
type UserVerifyKeyRes = Result<UserVerifyKeyData, SdkError>;

pub async fn fetch_user_public_key(base_url: String, auth_token: &str, user_id: &str) -> UserPublicKeyRes
{
	let url = base_url + "/api/v1/user/" + user_id + "/public_key";

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	#[cfg(not(feature = "export"))]
	let public_data = crate::util::public::import_public_key_from_string_into_format(res.as_str())?;

	#[cfg(feature = "export")]
	let public_data = crate::util::public::import_public_key_from_string_into_export_string(res.as_str())?;

	Ok(public_data)
}

pub async fn fetch_user_verify_key_by_id(base_url: String, auth_token: &str, user_id: &str, verify_key_id: &str) -> UserVerifyKeyRes
{
	let url = base_url + "/api/v1/user/" + user_id + "/verify_key/" + verify_key_id;

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	#[cfg(not(feature = "export"))]
	let public_data = crate::util::public::import_verify_key_from_string_into_format(res.as_str())?;

	#[cfg(feature = "export")]
	let (public_data, _) = crate::util::public::import_verify_key_from_string_into_export_string(res.as_str())?;

	Ok(public_data)
}

//__________________________________________________________________________________________________

pub fn prepare_done_key_rotation<'a>(base_url: String, auth_token: &'a str, jwt: &'a str) -> impl Future<Output = super::group::KeyRotationRes> + 'a
{
	super::group::prepare_done_key_rotation(base_url, auth_token, jwt, "", true, None)
}
