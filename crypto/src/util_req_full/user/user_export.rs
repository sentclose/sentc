use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_std_keys::util::{SecretKey, SignKey, SymKeyFormatExport, SymmetricKey};
use sentc_crypto_utils::cryptomat::{PkWrapper, SignKWrapper, SkWrapper, SymKeyWrapper, VerifyKWrapper};
use serde_json::from_str;

use crate::entities::user::{UserDataExport, UserKeyDataExport};
use crate::group::prepare_prepare_group_keys_for_new_member;
use crate::keys::std::{StdGroup, StdPreLoginOut, StdUser};
use crate::util_req_full::SessionKind;
use crate::{group, SdkError};

pub async fn register(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(StdUser::register_req(base_url, auth_token, user_identifier, password).await?)
}

pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(StdUser::register_device_start(base_url, auth_token, device_identifier, password).await?)
}

pub async fn register_device(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	server_output: &str,
	key_count: i32,
	user_keys: &str,
) -> Result<(Option<String>, String), String>
{
	let user_keys: Vec<SymKeyFormatExport> = from_str(user_keys).map_err(SdkError::JsonParseFailed)?;

	let saved_keys = user_keys
		.iter()
		.map(|k| k.try_into())
		.collect::<Result<Vec<SymmetricKey>, _>>()?;

	let split_group_keys = group::prepare_group_keys_for_new_member_with_ref(&saved_keys);

	let (session_id, exported_public_key) = StdUser::register_device(base_url, auth_token, jwt, server_output, key_count, &split_group_keys).await?;

	Ok((
		session_id,
		exported_public_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	))
}

pub async fn device_key_session(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	user_public_key: &str,
	group_keys: &str,
) -> Result<(), String>
{
	prepare_prepare_group_keys_for_new_member!(
		user_public_key,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::insert_session_keys(
				base_url,
				auth_token,
				jwt,
				"",
				SessionKind::UserGroup,
				session_id,
				&requester_public_key,
				&split_group_keys,
				None,
			)
			.await?)
		}
	)
}

//__________________________________________________________________________________________________
//Login

pub struct PrepareLoginOtpOutput
{
	pub master_key: String,
	pub auth_key: String,
}

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOutExport
{
	Direct(UserDataExport),
	Otp(PrepareLoginOtpOutput),
}

impl<S: SymKeyWrapper, Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper>
	TryFrom<super::PreLoginOut<S, Sk, Pk, SiK, Vk, sentc_crypto_std_keys::core::DeriveMasterKeyForAuth>> for PreLoginOutExport
{
	type Error = SdkError;

	fn try_from(value: super::PreLoginOut<S, Sk, Pk, SiK, Vk, sentc_crypto_std_keys::core::DeriveMasterKeyForAuth>) -> Result<Self, Self::Error>
	{
		match value {
			super::PreLoginOut::Direct(d) => Ok(Self::Direct(d.try_into()?)),
			super::PreLoginOut::Otp(d) => {
				let master_key: sentc_crypto_std_keys::util::MasterKeyFormat = d.master_key.into();

				Ok(Self::Otp(PrepareLoginOtpOutput {
					master_key: master_key.to_string()?,
					auth_key: d.auth_key,
				}))
			},
		}
	}
}

pub async fn login(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<PreLoginOutExport, String>
{
	let out: StdPreLoginOut = StdUser::login(base_url, auth_token, user_identifier, password).await?;

	Ok(out.try_into()?)
}

pub async fn mfa_login(
	base_url: String,
	auth_token: &str,
	master_key_encryption: &str,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> Result<UserDataExport, String>
{
	let master_key_encryption: sentc_crypto_std_keys::util::MasterKeyFormat = master_key_encryption.parse()?;
	let master_key_encryption: sentc_crypto_std_keys::core::DeriveMasterKeyForAuth = master_key_encryption.try_into()?;

	let out = StdUser::mfa_login(
		base_url,
		auth_token,
		&master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	)
	.await?;

	Ok(out.try_into()?)
}

pub async fn fetch_user_key(base_url: String, auth_token: &str, jwt: &str, key_id: &str, private_key: &str) -> Result<UserKeyDataExport, String>
{
	let private_key: SecretKey = private_key.parse()?;

	Ok(
		StdUser::fetch_user_key(base_url, auth_token, jwt, key_id, &private_key)
			.await?
			.try_into()?,
	)
}

//__________________________________________________________________________________________________

pub async fn get_fresh_jwt(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<String, String>
{
	Ok(StdUser::get_fresh_jwt(
		base_url,
		auth_token,
		user_identifier,
		password,
		mfa_token,
		mfa_recovery,
	)
	.await?)
}

pub async fn change_password(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	old_password: &str,
	new_password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<(), String>
{
	Ok(StdUser::change_password_req(
		base_url,
		auth_token,
		user_identifier,
		old_password,
		new_password,
		mfa_token,
		mfa_recovery,
	)
	.await?)
}

pub async fn reset_password(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	new_password: &str,
	decrypted_private_key: &str,
	decrypted_sign_key: &str,
) -> Result<(), String>
{
	let decrypted_private_key: SecretKey = decrypted_private_key.parse()?;
	let decrypted_sign_key: SignKey = decrypted_sign_key.parse()?;

	Ok(StdUser::reset_password_req(
		base_url,
		auth_token,
		jwt,
		new_password,
		&decrypted_private_key,
		&decrypted_sign_key,
	)
	.await?)
}

//__________________________________________________________________________________________________

pub async fn key_rotation(base_url: String, auth_token: &str, jwt: &str, device_public_key: &str, pre_user_key: &str) -> Result<String, String>
{
	super::super::group::key_rotation(
		base_url,
		auth_token,
		jwt,
		"",
		device_public_key,
		pre_user_key,
		true,
		None,
		Default::default(),
		None,
	)
	.await
}

pub async fn done_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	server_output: &str,
	pre_user_key: &str,
	device_public_key: &str,
	device_private_key: &str,
) -> Result<(), String>
{
	super::super::group::done_key_rotation(
		base_url,
		auth_token,
		jwt,
		"",
		server_output,
		pre_user_key,
		device_public_key,
		device_private_key,
		true,
		None,
	)
	.await
}
