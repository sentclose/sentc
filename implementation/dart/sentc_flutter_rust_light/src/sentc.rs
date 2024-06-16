use std::future::Future;

use once_cell::sync::OnceCell;
use sentc_crypto_light::util_req_full;
use tokio::runtime::Runtime;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();

pub type Result<T> = std::result::Result<T, String>;

fn rt<T, Fut>(fun: Fut) -> Result<T>
where
	Fut: Future<Output = std::result::Result<T, String>>,
{
	let rt = RUNTIME.get_or_init(|| {
		//init the tokio runtime
		Runtime::new().unwrap()
	});

	let data = rt.block_on(fun)?;

	Ok(data)
}

//==================================================================================================
//Jwt

#[repr(C)]
pub struct Claims
{
	pub aud: String,
	pub sub: String, //the app id
	pub exp: usize,
	pub iat: usize,
	pub fresh: bool, //was this token from refresh jwt or from login
}

impl From<sentc_crypto_common::user::Claims> for Claims
{
	fn from(claims: sentc_crypto_common::user::Claims) -> Self
	{
		Self {
			aud: claims.aud,
			sub: claims.sub,
			exp: claims.exp,
			iat: claims.iat,
			fresh: claims.fresh,
		}
	}
}

pub fn decode_jwt(jwt: String) -> Result<Claims>
{
	let claims = util_req_full::decode_jwt(&jwt)?;

	Ok(claims.into())
}

//==================================================================================================
//User

#[repr(C)]
pub struct GeneratedRegisterData
{
	pub identifier: String,
	pub password: String,
}

#[repr(C)]
pub struct DeviceKeyData
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto_light::DeviceKeyDataExport> for DeviceKeyData
{
	fn from(keys: sentc_crypto_light::DeviceKeyDataExport) -> Self
	{
		Self {
			private_key: keys.private_key,
			public_key: keys.public_key,
			sign_key: keys.sign_key,
			verify_key: keys.verify_key,
			exported_public_key: keys.exported_public_key,
			exported_verify_key: keys.exported_verify_key,
		}
	}
}

#[repr(C)]
pub struct UserDataExport
{
	pub jwt: String,
	pub user_id: String,
	pub device_id: String,
	pub refresh_token: String,
	pub device_keys: DeviceKeyData,
}

impl From<sentc_crypto_light::UserDataExport> for UserDataExport
{
	fn from(value: sentc_crypto_light::UserDataExport) -> Self
	{
		Self {
			jwt: value.jwt,
			user_id: value.user_id,
			device_id: value.device_id,
			refresh_token: value.refresh_token,
			device_keys: value.device_keys.into(),
		}
	}
}

#[repr(C)]
pub struct PrepareLoginOtpOutput
{
	pub master_key: String,
	pub auth_key: String,
}

impl From<util_req_full::user::PrepareLoginOtpOutput> for PrepareLoginOtpOutput
{
	fn from(value: util_req_full::user::PrepareLoginOtpOutput) -> Self
	{
		Self {
			master_key: value.master_key,
			auth_key: value.auth_key,
		}
	}
}

#[repr(C)]
pub struct UserLoginOut
{
	pub user_data: Option<UserDataExport>,

	pub mfa: Option<PrepareLoginOtpOutput>,
}

impl From<util_req_full::user::PreLoginOut> for UserLoginOut
{
	fn from(value: util_req_full::user::PreLoginOut) -> Self
	{
		match value {
			util_req_full::user::PreLoginOut::Direct(d) => {
				Self {
					mfa: None,
					user_data: Some(d.into()),
				}
			},
			util_req_full::user::PreLoginOut::Otp(d) => {
				Self {
					user_data: None,
					mfa: Some(d.into()),
				}
			},
		}
	}
}

//__________________________________________________________________________________________________

/**
# Check if the identifier is available for this app
 */
pub fn check_user_identifier_available(base_url: String, auth_token: String, user_identifier: String) -> Result<bool>
{
	let out = rt(util_req_full::user::check_user_identifier_available(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
	))?;

	Ok(out)
}

/**
Generates identifier and password for a user or device
 */
pub fn generate_user_register_data() -> Result<GeneratedRegisterData>
{
	let (identifier, password) = sentc_crypto_light::user::generate_user_register_data()?;

	Ok(GeneratedRegisterData {
		identifier,
		password,
	})
}

/**
# Get the user input from the user client

This is used when the register endpoint should only be called from the backend and not the clients.

For full register see register()
 */
pub fn prepare_register(user_identifier: String, password: String) -> Result<String>
{
	sentc_crypto_light::user::register(user_identifier.as_str(), password.as_str())
}

/**
# Validates the response of register

Returns the new user id
 */
pub fn done_register(server_output: String) -> Result<String>
{
	sentc_crypto_light::user::done_register(server_output.as_str())
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
pub fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String>
{
	let data = rt(util_req_full::user::register(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(data)
}

pub fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String>
{
	let out = rt(util_req_full::user::register_device_start(
		base_url,
		auth_token.as_str(),
		device_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(out)
}

pub fn done_register_device_start(server_output: String) -> Result<()>
{
	sentc_crypto_light::user::done_register_device_start(server_output.as_str())
}

pub fn register_device(base_url: String, auth_token: String, jwt: String, server_output: String) -> Result<()>
{
	rt(util_req_full::user::register_device(
		base_url,
		&auth_token,
		&jwt,
		&server_output,
	))
}

/**
# Login the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there are more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
pub fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserLoginOut>
{
	let data = rt(util_req_full::user::login(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(data.into())
}

pub fn mfa_login(
	base_url: String,
	auth_token: String,
	master_key_encryption: String,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> Result<UserDataExport>
{
	let data = rt(util_req_full::user::mfa_login(
		base_url,
		&auth_token,
		&master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	))?;

	Ok(data.into())
}

pub fn get_fresh_jwt(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<String>
{
	rt(util_req_full::user::get_fresh_jwt(
		base_url,
		&auth_token,
		&user_identifier,
		&password,
		mfa_token,
		mfa_recovery,
	))
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserInitServerOutput
{
	pub jwt: String,
	pub invites: Vec<GroupInviteReqList>,
}

pub fn refresh_jwt(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<String>
{
	rt(util_req_full::user::refresh_jwt(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		refresh_token,
	))
}

pub fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput>
{
	let out = rt(util_req_full::user::init_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		refresh_token,
	))?;

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites: out
			.invites
			.into_iter()
			.map(|invite| invite.into())
			.collect(),
	})
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserDeviceList
{
	pub device_id: String,
	pub time: String,
	pub device_identifier: String,
}

impl From<sentc_crypto_common::user::UserDeviceList> for UserDeviceList
{
	fn from(list: sentc_crypto_common::user::UserDeviceList) -> Self
	{
		Self {
			device_id: list.device_id,
			time: list.time.to_string(),
			device_identifier: list.device_identifier,
		}
	}
}

pub fn get_user_devices(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_id: String,
) -> Result<Vec<UserDeviceList>>
{
	let out = rt(util_req_full::user::get_user_devices(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//no pw reset because this is server side only

pub fn change_password(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	old_password: String,
	new_password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<()>
{
	rt(util_req_full::user::change_password(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		old_password.as_str(),
		new_password.as_str(),
		mfa_token,
		mfa_recovery,
	))
}

pub fn delete_user(base_url: String, auth_token: String, fresh_jwt: String) -> Result<()>
{
	rt(util_req_full::user::delete(base_url, auth_token.as_str(), &fresh_jwt))
}

pub fn delete_device(base_url: String, auth_token: String, fresh_jwt: String, device_id: String) -> Result<()>
{
	rt(util_req_full::user::delete_device(
		base_url,
		auth_token.as_str(),
		&fresh_jwt,
		&device_id,
	))
}

pub fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<()>
{
	rt(util_req_full::user::update(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		user_identifier,
	))
}

//__________________________________________________________________________________________________
//Otp

#[repr(C)]
pub struct OtpRegister
{
	pub secret: String, //base32 endowed secret
	pub alg: String,
	pub recover: Vec<String>,
}

impl From<sentc_crypto_common::user::OtpRegister> for OtpRegister
{
	fn from(value: sentc_crypto_common::user::OtpRegister) -> Self
	{
		Self {
			secret: value.secret,
			alg: value.alg,
			recover: value.recover,
		}
	}
}

#[repr(C)]
pub struct OtpRegisterUrl
{
	pub url: String,
	pub recover: Vec<String>,
}

#[repr(C)]
pub struct OtpRecoveryKeysOutput
{
	pub keys: Vec<String>,
}

impl From<sentc_crypto_common::user::OtpRecoveryKeysOutput> for OtpRecoveryKeysOutput
{
	fn from(value: sentc_crypto_common::user::OtpRecoveryKeysOutput) -> Self
	{
		Self {
			keys: value.keys,
		}
	}
}

pub fn register_raw_otp(base_url: String, auth_token: String, jwt: String) -> Result<OtpRegister>
{
	let out = rt(util_req_full::user::register_raw_otp(base_url, &auth_token, &jwt))?;

	Ok(out.into())
}

pub fn register_otp(base_url: String, auth_token: String, jwt: String, issuer: String, audience: String) -> Result<OtpRegisterUrl>
{
	let (url, recover) = rt(util_req_full::user::register_otp(
		base_url,
		&auth_token,
		&issuer,
		&audience,
		&jwt,
	))?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

pub fn get_otp_recover_keys(base_url: String, auth_token: String, jwt: String) -> Result<OtpRecoveryKeysOutput>
{
	let out = rt(util_req_full::user::get_otp_recover_keys(base_url, &auth_token, &jwt))?;

	Ok(out.into())
}

pub fn reset_raw_otp(base_url: String, auth_token: String, jwt: String) -> Result<OtpRegister>
{
	let out = rt(util_req_full::user::reset_raw_otp(base_url, &auth_token, &jwt))?;

	Ok(out.into())
}

pub fn reset_otp(base_url: String, auth_token: String, jwt: String, issuer: String, audience: String) -> Result<OtpRegisterUrl>
{
	let (url, recover) = rt(util_req_full::user::reset_otp(
		base_url,
		&auth_token,
		&jwt,
		&issuer,
		&audience,
	))?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

pub fn disable_otp(base_url: String, auth_token: String, jwt: String) -> Result<()>
{
	rt(util_req_full::user::disable_otp(base_url, &auth_token, &jwt))
}

//==================================================================================================
//group

#[repr(C)]
pub struct GroupOutDataLightExport
{
	pub group_id: String,
	pub parent_group_id: Option<String>,
	pub rank: i32,
	pub created_time: String,
	pub joined_time: String,
	pub access_by_group_as_member: Option<String>,
	pub access_by_parent_group: Option<String>,
	pub is_connected_group: bool,
}

impl From<sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport> for GroupOutDataLightExport
{
	fn from(value: sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport) -> Self
	{
		Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			created_time: value.created_time.to_string(),
			joined_time: value.joined_time.to_string(),
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		}
	}
}

#[repr(C)]
pub struct GroupInviteReqList
{
	pub group_id: String,
	pub time: String,
}

impl From<sentc_crypto_common::group::GroupInviteReqList> for GroupInviteReqList
{
	fn from(list: sentc_crypto_common::group::GroupInviteReqList) -> Self
	{
		Self {
			group_id: list.group_id,
			time: list.time.to_string(),
		}
	}
}

/**
Create a group with request.

Only the default values are send to the server, no extra data. If extra data is required, use prepare_create
 */
pub fn group_create_group(base_url: String, auth_token: String, jwt: String, group_as_member: Option<String>) -> Result<String>
{
	rt(util_req_full::group::create(
		base_url,
		&auth_token,
		&jwt,
		group_as_member.as_deref(),
	))
}

pub fn group_create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String>
{
	rt(util_req_full::group::create_child_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		parent_id.as_str(),
		admin_rank,
		group_as_member.as_deref(),
	))
}

pub fn group_create_connected_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	connected_group_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String>
{
	rt(util_req_full::group::create_connected_group(
		base_url,
		&auth_token,
		&jwt,
		&connected_group_id,
		admin_rank,
		group_as_member.as_deref(),
	))
}

//__________________________________________________________________________________________________

/**
Get the group data without request.

Use the parent group private key when fetching child group data.
 */
pub fn group_extract_group_data(server_output: String) -> Result<GroupOutDataLightExport>
{
	let out = sentc_crypto_light::group::get_group_light_data(server_output.as_str())?;

	Ok(out.into())
}

pub fn group_get_group_data(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: Option<String>,
) -> Result<GroupOutDataLightExport>
{
	let out = rt(util_req_full::group::get_group_light(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into())
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct GroupUserListItem
{
	pub user_id: String,
	pub rank: i32,
	pub joined_time: String,
	pub user_type: i32,
}

impl From<sentc_crypto_common::group::GroupUserListItem> for GroupUserListItem
{
	fn from(item: sentc_crypto_common::group::GroupUserListItem) -> Self
	{
		Self {
			user_id: item.user_id,
			rank: item.rank,
			joined_time: item.joined_time.to_string(),
			user_type: item.user_type,
		}
	}
}

#[repr(C)]
pub struct GroupChildrenList
{
	pub group_id: String,
	pub time: String,
	pub parent: Option<String>,
}

impl From<sentc_crypto_common::group::GroupChildrenList> for GroupChildrenList
{
	fn from(i: sentc_crypto_common::group::GroupChildrenList) -> Self
	{
		Self {
			group_id: i.group_id,
			time: i.time.to_string(),
			parent: i.parent,
		}
	}
}

#[repr(C)]
pub struct ListGroups
{
	pub group_id: String,
	pub time: String,
	pub joined_time: String,
	pub rank: i32,
	pub parent: Option<String>,
}

impl From<sentc_crypto_common::group::ListGroups> for ListGroups
{
	fn from(item: sentc_crypto_common::group::ListGroups) -> Self
	{
		Self {
			group_id: item.group_id,
			time: item.time.to_string(),
			joined_time: item.joined_time.to_string(),
			rank: item.rank,
			parent: item.parent,
		}
	}
}

pub fn group_get_member(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupUserListItem>>
{
	let out = rt(util_req_full::group::get_member(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_get_group_updates(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: Option<String>) -> Result<i32>
{
	rt(util_req_full::group::get_group_updates(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_as_member.as_deref(),
	))
}

pub fn group_get_all_first_level_children(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupChildrenList>>
{
	let out = rt(util_req_full::group::get_all_first_level_children(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&last_fetched_time,
		&last_fetched_group_id,
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_get_groups_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: Option<String>,
) -> Result<Vec<ListGroups>>
{
	let out = rt(util_req_full::group::get_groups_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_id.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________
//invite

#[allow(clippy::too_many_arguments)]
pub fn group_invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::invite_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		group_as_member.as_deref(),
	))
}

pub fn group_get_invites_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = rt(util_req_full::group::get_invites_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_id.as_deref(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_accept_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::accept_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id.as_deref(),
		group_as_member.as_deref(),
	))
}

pub fn group_reject_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::reject_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id.as_deref(),
		group_as_member.as_deref(),
	))
}

//__________________________________________________________________________________________________
//join req

#[repr(C)]
pub struct GroupJoinReqList
{
	pub user_id: String,
	pub time: String,
	pub user_type: i32,
}

impl From<sentc_crypto_common::group::GroupJoinReqList> for GroupJoinReqList
{
	fn from(list: sentc_crypto_common::group::GroupJoinReqList) -> Self
	{
		Self {
			user_id: list.user_id,
			time: list.time.to_string(),
			user_type: list.user_type,
		}
	}
}

pub fn group_get_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = rt(util_req_full::group::get_sent_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		None,
		None,
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[allow(clippy::too_many_arguments)]
pub fn group_get_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = rt(util_req_full::group::get_sent_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		Some(&id),
		Some(admin_rank),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_delete_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	join_req_group_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		None,
		None,
		&join_req_group_id,
		group_as_member.as_deref(),
	))
}

pub fn group_delete_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	join_req_group_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&join_req_group_id,
		group_as_member.as_deref(),
	))
}

pub fn group_join_req(base_url: String, auth_token: String, jwt: String, id: String, group_id: String, group_as_member: Option<String>)
	-> Result<()>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	rt(util_req_full::group::join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		group_as_member.as_deref(),
	))
}

#[allow(clippy::too_many_arguments)]
pub fn group_get_join_reqs(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupJoinReqList>>
{
	let out = rt(util_req_full::group::get_join_reqs(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
		group_as_member.as_deref(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_reject_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	rejected_user_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::reject_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		rejected_user_id.as_str(),
		group_as_member.as_deref(),
	))
}

#[allow(clippy::too_many_arguments)]
pub fn group_accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: Option<i32>,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::accept_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
		group_as_member.as_deref(),
	))
}

pub fn group_stop_group_invites(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::stop_group_invites(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		group_as_member.as_deref(),
	))
}

//__________________________________________________________________________________________________

pub fn leave_group(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: Option<String>) -> Result<()>
{
	rt(util_req_full::group::leave_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_as_member.as_deref(),
	))
}

//__________________________________________________________________________________________________
//group update fn

pub fn group_prepare_update_rank(user_id: String, rank: i32, admin_rank: i32) -> Result<String>
{
	sentc_crypto_light::group::prepare_change_rank(&user_id, rank, admin_rank)
}

#[allow(clippy::too_many_arguments)]
pub fn group_update_rank(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::update_rank(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
		group_as_member.as_deref(),
	))
}

pub fn group_kick_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::kick_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		admin_rank,
		group_as_member.as_deref(),
	))
}

//__________________________________________________________________________________________________

pub fn group_delete_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	rt(util_req_full::group::delete_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		group_as_member.as_deref(),
	))
}
