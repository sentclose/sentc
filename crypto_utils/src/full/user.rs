use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sentc_crypto_common::user::{
	DoneLoginServerOutput,
	DoneLoginServerReturn,
	OtpRecoveryKeysOutput,
	OtpRegister,
	UserDeviceList,
	UserInitServerOutput,
};
use sentc_crypto_core::cryptomat::PwHash;
use sentc_crypto_core::DeriveMasterKeyForAuth;

use crate::cryptomat::{PkWrapper, SignComposerWrapper, SignKWrapper, SkWrapper, StaticKeyComposerWrapper, VerifyKWrapper};
use crate::error::SdkUtilError;
use crate::http::{auth_req, non_auth_req, HttpMethod};
use crate::user::UserPreVerifyLogin;
use crate::{handle_general_server_response, handle_server_response};

pub struct PrepareLoginOtpOutput
{
	pub master_key: DeriveMasterKeyForAuth,
	pub auth_key: String,
}

#[allow(clippy::large_enum_variant)]
pub enum PreLoginOut<Sk: SkWrapper, Pk: PkWrapper, SiK: SignKWrapper, Vk: VerifyKWrapper>
{
	Direct(UserPreVerifyLogin<Sk, Pk, SiK, Vk>),
	Otp(PrepareLoginOtpOutput),
}

//__________________________________________________________________________________________________
//Login

async fn prepare_login_start(base_url: String, auth_token: &str, user_identifier: &str) -> Result<String, SdkUtilError>
{
	let user_id_input = crate::user::prepare_login_start(user_identifier)?;

	let url = base_url + "/api/v1/prepare_login";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(user_id_input)).await?;

	Ok(res)
}

async fn done_login_internally<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper, PwH: PwHash>(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	prepare_login_res: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<
	(
		UserPreVerifyLogin<
			<SkC as StaticKeyComposerWrapper>::SkWrapper,
			<SkC as StaticKeyComposerWrapper>::PkWrapper,
			<SiKC as SignComposerWrapper>::SignKWrapper,
			<SiKC as SignComposerWrapper>::VerifyKWrapper,
		>,
		DoneLoginServerOutput,
	),
	SdkUtilError,
>
{
	let (input, auth_key, master_key) = crate::user::prepare_login::<PwH>(user_identifier, password, prepare_login_res)?;

	let url = base_url.clone() + "/api/v1/done_login";
	let server_out = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	match crate::user::check_done_login(&server_out)? {
		DoneLoginServerReturn::Direct(d) => {
			let out = crate::user::done_login::<SkC, SiKC>(&master_key, auth_key, user_identifier.to_string(), d.clone())?;

			Ok((out, d))
		},
		DoneLoginServerReturn::Otp => {
			//if user enables mfa it must be saved in the user data, so the token is needed before doing the req
			let mfa_token = mfa_token.ok_or(SdkUtilError::JsonToStringFailed)?;
			let mfa_recovery = mfa_recovery.ok_or(SdkUtilError::JsonToStringFailed)?;

			//use this with the token of the auth app but without to verify

			let url = base_url.clone() +
				if mfa_recovery {
					"/api/v1/validate_recovery_otp"
				} else {
					"/api/v1/validate_mfa"
				};

			let input = crate::user::prepare_validate_mfa(auth_key.clone(), user_identifier.to_string(), mfa_token)?;

			let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

			let d: DoneLoginServerOutput = handle_server_response(&res)?;

			let out = crate::user::done_login::<SkC, SiKC>(&master_key, auth_key, user_identifier.to_string(), d.clone())?;

			Ok((out, d))
		},
	}
}

/**
Do the full login process, except of the verify login because this is different from sdk light or normal version
*/
pub async fn login<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper, PwH: PwHash>(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
) -> Result<
	PreLoginOut<
		<SkC as StaticKeyComposerWrapper>::SkWrapper,
		<SkC as StaticKeyComposerWrapper>::PkWrapper,
		<SiKC as SignComposerWrapper>::SignKWrapper,
		<SiKC as SignComposerWrapper>::VerifyKWrapper,
	>,
	SdkUtilError,
>
{
	let user_id_input = crate::user::prepare_login_start(user_identifier)?;

	let url = base_url.clone() + "/api/v1/prepare_login";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(user_id_input)).await?;

	//prepare the login, the auth key is already in the right json format for the server
	let (input, auth_key, master_key_encryption_key) = crate::user::prepare_login::<PwH>(user_identifier, password, &res)?;

	let url = base_url + "/api/v1/done_login";
	let server_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(input)).await?;

	match crate::user::check_done_login(&server_out)? {
		DoneLoginServerReturn::Direct(d) => {
			let verify = crate::user::done_login::<SkC, SiKC>(&master_key_encryption_key, auth_key, user_identifier.to_string(), d)?;

			Ok(PreLoginOut::Direct(verify))
		},
		DoneLoginServerReturn::Otp => {
			//export the data needed for this fn

			Ok(PreLoginOut::Otp(PrepareLoginOtpOutput {
				master_key: master_key_encryption_key,
				auth_key,
			}))
		},
	}
}

pub async fn mfa_login<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper>(
	base_url: String,
	auth_token: &str,
	master_key_encryption: &DeriveMasterKeyForAuth,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
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
	//use this with the token of the auth app

	let url = base_url +
		if recovery {
			"/api/v1/validate_recovery_otp"
		} else {
			"/api/v1/validate_mfa"
		};

	let input = crate::user::prepare_validate_mfa(auth_key.clone(), user_identifier.clone(), token)?;

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	let keys = crate::user::done_validate_mfa::<SkC, SiKC>(master_key_encryption, auth_key, user_identifier, &res)?;

	Ok(keys)
}

//__________________________________________________________________________________________________

pub async fn refresh_jwt(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Result<String, SdkUtilError>
{
	let input = crate::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/refresh";

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	let server_output: sentc_crypto_common::user::DoneLoginLightServerOutput = handle_server_response(res.as_str())?;

	Ok(server_output.jwt)
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Result<UserInitServerOutput, SdkUtilError>
{
	let input = crate::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/init";

	let res = auth_req(HttpMethod::POST, &url, auth_token, Some(input), jwt).await?;

	handle_server_response(&res)
}

pub async fn get_user_devices(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
) -> Result<Vec<UserDeviceList>, SdkUtilError>
{
	let url = base_url + "/api/v1/user/device/" + last_fetched_time + "/" + last_fetched_id;

	let res = auth_req(HttpMethod::GET, url.as_str(), auth_token, None, jwt).await?;

	handle_server_response(&res)
}

//__________________________________________________________________________________________________

pub async fn prepare_user_fresh_jwt<SkC: StaticKeyComposerWrapper, SiKC: SignComposerWrapper, PwH: PwHash>(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<
	(
		String,
		UserPreVerifyLogin<
			<SkC as StaticKeyComposerWrapper>::SkWrapper,
			<SkC as StaticKeyComposerWrapper>::PkWrapper,
			<SiKC as SignComposerWrapper>::SignKWrapper,
			<SiKC as SignComposerWrapper>::VerifyKWrapper,
		>,
		DoneLoginServerOutput,
	),
	SdkUtilError,
>
{
	//first make the prep login req to get the output
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, user_identifier).await?;

	let (keys, done_login_out) = done_login_internally::<SkC, SiKC, PwH>(
		base_url,
		auth_token,
		user_identifier,
		password,
		&prep_login_out,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	Ok((prep_login_out, keys, done_login_out))
}

//__________________________________________________________________________________________________

pub async fn update(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> Result<(), SdkUtilError>
{
	let url = base_url + "/api/v1/user";

	let input = crate::user::prepare_user_identifier_update(user_identifier)?;

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	handle_general_server_response(&res)
}

pub async fn done_change_password<PwH: PwHash>(
	base_url: String,
	auth_token: &str,
	old_password: &str,
	new_password: &str,
	fresh_jwt: &str,
	pre_login_out: &str,
	done_login_out: DoneLoginServerOutput,
) -> Result<(), SdkUtilError>
{
	let change_pw_input = crate::user::change_password::<PwH>(old_password, new_password, pre_login_out, done_login_out)?;

	let url = base_url + "/api/v1/user/update_pw";

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(change_pw_input), fresh_jwt).await?;

	handle_general_server_response(&res)
}

pub async fn done_delete(base_url: String, auth_token: &str, fresh_jwt: &str) -> Result<(), SdkUtilError>
{
	let url = base_url + "/api/v1/user";

	let res = auth_req(HttpMethod::DELETE, &url, auth_token, None, fresh_jwt).await?;

	handle_general_server_response(&res)
}

pub async fn done_delete_device(base_url: String, auth_token: &str, fresh_jwt: &str, device_id: &str) -> Result<(), SdkUtilError>
{
	let url = base_url + "/api/v1/user/device/" + device_id;

	let res = auth_req(HttpMethod::DELETE, url.as_str(), auth_token, None, fresh_jwt).await?;

	handle_general_server_response(&res)
}

//__________________________________________________________________________________________________
//Otp

pub async fn register_raw_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRegister, SdkUtilError>
{
	let url = base_url + "/api/v1/user/register_otp";

	let res = auth_req(HttpMethod::PATCH, &url, auth_token, None, jwt).await?;

	handle_server_response(&res)
}

pub async fn register_otp(base_url: String, auth_token: &str, jwt: &str, issuer: &str, audience: &str)
	-> Result<(String, Vec<String>), SdkUtilError>
{
	let out = register_raw_otp(base_url, auth_token, jwt).await?;

	Ok((create_otp_url(issuer, audience, &out.secret), out.recover))
}

fn create_otp_url(issuer: &str, audience: &str, secret: &str) -> String
{
	"otpauth://totp/".to_string() + issuer + ":" + audience + "?secret=" + secret + "&algorithm=SHA256&issuer=" + issuer
}

pub async fn get_otp_recover_keys(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRecoveryKeysOutput, SdkUtilError>
{
	let url = base_url + "/api/v1/user/otp_recovery_keys";

	let res = auth_req(HttpMethod::GET, &url, auth_token, None, jwt).await?;

	handle_server_response(&res)
}

pub async fn reset_raw_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRegister, SdkUtilError>
{
	let url = base_url + "/api/v1/user/reset_otp";

	let res = auth_req(HttpMethod::PATCH, &url, auth_token, None, jwt).await?;

	handle_server_response(&res)
}

pub async fn reset_otp(base_url: String, auth_token: &str, jwt: &str, issuer: &str, audience: &str) -> Result<(String, Vec<String>), SdkUtilError>
{
	let out = reset_raw_otp(base_url, auth_token, jwt).await?;

	Ok((create_otp_url(issuer, audience, &out.secret), out.recover))
}

pub async fn disable_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<(), SdkUtilError>
{
	let url = base_url + "/api/v1/user/disable_otp";

	let res = auth_req(HttpMethod::PATCH, &url, auth_token, None, jwt).await?;

	handle_general_server_response(&res)
}
