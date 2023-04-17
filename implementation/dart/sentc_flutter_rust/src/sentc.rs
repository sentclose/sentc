use std::future::Future;

use anyhow::{anyhow, Result};
use flutter_rust_bridge::ZeroCopyBuffer;
use once_cell::sync::OnceCell;
use sentc_crypto::user;
use tokio::runtime::Runtime;

static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn rt<T, Fut>(fun: Fut) -> Result<T>
where
	Fut: Future<Output = std::result::Result<T, String>>,
{
	let rt = RUNTIME.get_or_init(|| {
		//init the tokio runtime
		Runtime::new().unwrap()
	});

	let data = rt.block_on(fun).map_err(|err| anyhow!(err))?;

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
	let claims = sentc_crypto_full::jwt::decode_jwt(&jwt).map_err(|err| anyhow!(err))?;

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
pub struct PrepareLoginOutput
{
	pub auth_key: String,
	pub master_key_encryption_key: String,
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

impl From<sentc_crypto::util::DeviceKeyData> for DeviceKeyData
{
	fn from(keys: sentc_crypto::DeviceKeyData) -> Self
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
pub struct UserKeyData
{
	pub private_key: String,
	pub public_key: String,
	pub group_key: String,
	pub time: String,
	pub group_key_id: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::util::UserKeyData> for UserKeyData
{
	fn from(data: sentc_crypto::UserKeyData) -> Self
	{
		Self {
			private_key: data.private_key,
			public_key: data.public_key,
			group_key: data.group_key,
			time: data.time.to_string(),
			group_key_id: data.group_key_id,
			sign_key: data.sign_key,
			verify_key: data.verify_key,
			exported_public_key: data.exported_public_key,
			exported_verify_key: data.exported_verify_key,
		}
	}
}

#[repr(C)]
pub struct UserData
{
	pub jwt: String,
	pub user_id: String,
	pub device_id: String,
	pub refresh_token: String,
	pub keys: DeviceKeyData,
	pub user_keys: Vec<UserKeyData>,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
}

impl From<sentc_crypto::util::UserData> for UserData
{
	fn from(data: sentc_crypto::UserData) -> Self
	{
		Self {
			jwt: data.jwt,
			user_id: data.user_id,
			device_id: data.device_id,
			refresh_token: data.refresh_token,
			keys: data.device_keys.into(),
			user_keys: data
				.user_keys
				.into_iter()
				.map(|user_key| user_key.into())
				.collect(),
			hmac_keys: data
				.hmac_keys
				.into_iter()
				.map(|hmac_key| hmac_key.into())
				.collect(),
		}
	}
}

//__________________________________________________________________________________________________

/**
# Check if the identifier is available for this app
 */
pub fn check_user_identifier_available(base_url: String, auth_token: String, user_identifier: String) -> Result<bool>
{
	let out = rt(sentc_crypto_full::user::check_user_identifier_available(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
	))?;

	Ok(out)
}

/**
# Check if the identifier is available

but without making a request
 */
pub fn prepare_check_user_identifier_available(user_identifier: String) -> Result<String>
{
	user::prepare_check_user_identifier_available(user_identifier.as_str()).map_err(|err| anyhow!(err))
}

/**
# Validates the response if the identifier is available

but without making a request
 */
pub fn done_check_user_identifier_available(server_output: String) -> Result<bool>
{
	user::done_check_user_identifier_available(server_output.as_str()).map_err(|err| anyhow!(err))
}

/**
Generates identifier and password for a user or device
*/
pub fn generate_user_register_data() -> Result<GeneratedRegisterData>
{
	let (identifier, password) = user::generate_user_register_data().map_err(|err| anyhow!(err))?;

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
	user::register(user_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

/**
# Validates the response of register

Returns the new user id
 */
pub fn done_register(server_output: String) -> Result<String>
{
	user::done_register(server_output.as_str()).map_err(|err| anyhow!(err))
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
pub fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String>
{
	let data = rt(sentc_crypto_full::user::register(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(data)
}

pub fn prepare_register_device_start(device_identifier: String, password: String) -> Result<String>
{
	user::prepare_register_device_start(device_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

pub fn done_register_device_start(server_output: String) -> Result<()>
{
	user::done_register_device_start(server_output.as_str()).map_err(|err| anyhow!(err))
}

pub fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String>
{
	let out = rt(sentc_crypto_full::user::register_device_start(
		base_url,
		auth_token.as_str(),
		device_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(out)
}

#[repr(C)]
pub struct PreRegisterDeviceData
{
	pub input: String,
	pub exported_public_key: String,
}

#[repr(C)]
pub struct RegisterDeviceData
{
	pub session_id: String,
	pub exported_public_key: String,
}

pub fn prepare_register_device(server_output: String, user_keys: String, key_count: i32) -> Result<PreRegisterDeviceData>
{
	let key_session = key_count > 50;

	let (input, exported_public_key) = user::prepare_register_device(
		//
		server_output.as_str(),
		user_keys.as_str(),
		key_session,
	)
	.map_err(|err| anyhow!(err))?;

	Ok(PreRegisterDeviceData {
		input,
		exported_public_key,
	})
}

pub fn register_device(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	key_count: i32,
	user_keys: String,
) -> Result<RegisterDeviceData>
{
	let (out, exported_public_key) = rt(sentc_crypto_full::user::register_device(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		server_output.as_str(),
		key_count,
		user_keys.as_str(),
	))?;

	let session_id = match out {
		Some(id) => id,
		None => String::from(""),
	};

	Ok(RegisterDeviceData {
		session_id,
		exported_public_key,
	})
}

pub fn user_device_key_session_upload(
	base_url: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
) -> Result<()>
{
	rt(sentc_crypto_full::user::device_key_session(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		user_public_key.as_str(),
		group_keys.as_str(),
	))
}

//__________________________________________________________________________________________________

pub fn prepare_login_start(base_url: String, auth_token: String, user_identifier: String) -> Result<String>
{
	let out = rt(sentc_crypto_full::user::prepare_login_start(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
	))?;

	Ok(out)
}

pub fn prepare_login(user_identifier: String, password: String, server_output: String) -> Result<PrepareLoginOutput>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(
		//
		user_identifier.as_str(),
		password.as_str(),
		server_output.as_str(),
	)
	.map_err(|err| anyhow!(err))?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> Result<UserData>
{
	let data = user::done_login(master_key_encryption.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(data.into())
}

/**
# Login the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there are more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
pub fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserData>
{
	let data = rt(sentc_crypto_full::user::login(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	))?;

	Ok(data.into())
}

pub fn done_fetch_user_key(private_key: String, server_output: String) -> Result<UserKeyData>
{
	let data = user::done_key_fetch(private_key.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(data.into())
}

pub fn fetch_user_key(base_url: String, auth_token: String, jwt: String, key_id: String, private_key: String) -> Result<UserKeyData>
{
	let data = rt(sentc_crypto_full::user::fetch_user_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		key_id.as_str(),
		private_key.as_str(),
	))?;

	Ok(data.into())
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
	rt(sentc_crypto_full::user::refresh_jwt(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		refresh_token.as_str(),
	))
}

pub fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput>
{
	let out = rt(sentc_crypto_full::user::init_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		refresh_token.as_str(),
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
	let out = rt(sentc_crypto_full::user::get_user_devices(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn reset_password(
	base_url: String,
	auth_token: String,
	jwt: String,
	new_password: String,
	decrypted_private_key: String,
	decrypted_sign_key: String,
) -> Result<()>
{
	rt(sentc_crypto_full::user::reset_password(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		new_password.as_str(),
		decrypted_private_key.as_str(),
		decrypted_sign_key.as_str(),
	))
}

pub fn change_password(base_url: String, auth_token: String, user_identifier: String, old_password: String, new_password: String) -> Result<()>
{
	rt(sentc_crypto_full::user::change_password(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		old_password.as_str(),
		new_password.as_str(),
	))
}

pub fn delete_user(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<()>
{
	rt(sentc_crypto_full::user::delete(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	))
}

pub fn delete_device(base_url: String, auth_token: String, device_identifier: String, password: String, device_id: String) -> Result<()>
{
	rt(sentc_crypto_full::user::delete_device(
		base_url,
		auth_token.as_str(),
		device_identifier.as_str(),
		password.as_str(),
		device_id.as_str(),
	))
}

pub fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<()>
{
	rt(sentc_crypto_full::user::update(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		user_identifier,
	))
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
}

pub fn user_fetch_public_key(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicKeyData>
{
	let (public_key, public_key_id) = rt(sentc_crypto_full::user::fetch_user_public_key(
		base_url,
		auth_token.as_str(),
		user_id.as_str(),
	))?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
	})
}

pub fn user_fetch_verify_key(base_url: String, auth_token: String, user_id: String, verify_key_id: String) -> Result<String>
{
	let key = rt(sentc_crypto_full::user::fetch_user_verify_key_by_id(
		base_url,
		auth_token.as_str(),
		user_id.as_str(),
		verify_key_id.as_str(),
	))?;

	Ok(key)
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub new_group_key_id: String,
	pub encrypted_eph_key_key_id: String,
	pub server_output: String,
}

pub fn user_key_rotation(base_url: String, auth_token: String, jwt: String, public_device_key: String, pre_user_key: String) -> Result<String>
{
	rt(sentc_crypto_full::user::key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		public_device_key.as_str(),
		pre_user_key.as_str(),
	))
}

pub fn user_pre_done_key_rotation(base_url: String, auth_token: String, jwt: String) -> Result<Vec<KeyRotationGetOut>>
{
	let out = rt(sentc_crypto_full::user::prepare_done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
	))?;

	let mut list = Vec::with_capacity(out.len());

	for item in out {
		list.push(KeyRotationGetOut {
			pre_group_key_id: item.pre_group_key_id,
			new_group_key_id: item.new_group_key_id,
			encrypted_eph_key_key_id: item.encrypted_eph_key_key_id,
			server_output: item.server_output,
		});
	}

	Ok(list)
}

pub fn user_get_done_key_rotation_server_input(server_output: String) -> Result<KeyRotationInput>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

pub fn user_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
) -> Result<()>
{
	rt(sentc_crypto_full::user::done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		server_output.as_str(),
		pre_group_key.as_str(),
		public_key.as_str(),
		private_key.as_str(),
	))
}

//==================================================================================================
//Group

#[repr(C)]
pub struct GroupKeyData
{
	pub private_group_key: String,
	pub public_group_key: String,
	pub exported_public_key: String,
	pub group_key: String,
	pub time: String,
	pub group_key_id: String,
}

impl From<sentc_crypto::group::GroupKeyData> for GroupKeyData
{
	fn from(data: sentc_crypto::group::GroupKeyData) -> Self
	{
		Self {
			private_group_key: data.private_group_key,
			public_group_key: data.public_group_key,
			exported_public_key: data.exported_public_key,
			group_key: data.group_key,
			time: data.time.to_string(),
			group_key_id: data.group_key_id,
		}
	}
}

#[repr(C)]
pub struct GroupOutDataKeys
{
	pub private_key_id: String,
	pub key_data: String, //serde string
}

impl From<sentc_crypto::group::GroupOutDataKeys> for GroupOutDataKeys
{
	fn from(key: sentc_crypto::group::GroupOutDataKeys) -> Self
	{
		Self {
			private_key_id: key.private_key_id,
			key_data: key.key_data,
		}
	}
}

#[repr(C)]
pub struct GroupOutDataHmacKeys
{
	pub group_key_id: String,
	pub key_data: String, //serde string
}

impl From<sentc_crypto::group::GroupOutDataHmacKeys> for GroupOutDataHmacKeys
{
	fn from(key: sentc_crypto::group::GroupOutDataHmacKeys) -> Self
	{
		Self {
			group_key_id: key.group_key_id,
			key_data: key.key_data,
		}
	}
}

#[repr(C)]
pub struct GroupOutData
{
	pub group_id: String,
	pub parent_group_id: String,
	pub rank: i32,
	pub key_update: bool,
	pub created_time: String,
	pub joined_time: String,
	pub keys: Vec<GroupOutDataKeys>,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
	pub access_by_group_as_member: Option<String>,
	pub access_by_parent_group: Option<String>,
	pub is_connected_group: bool,
}

impl From<sentc_crypto::group::GroupOutData> for GroupOutData
{
	fn from(data: sentc_crypto::group::GroupOutData) -> Self
	{
		Self {
			group_id: data.group_id,
			parent_group_id: data.parent_group_id,
			rank: data.rank,
			key_update: data.key_update,
			created_time: data.created_time.to_string(),
			joined_time: data.joined_time.to_string(),
			keys: data.keys.into_iter().map(|key| key.into()).collect(),
			hmac_keys: data
				.hmac_keys
				.into_iter()
				.map(|hmac_key| hmac_key.into())
				.collect(),
			access_by_group_as_member: data.access_by_group_as_member,
			access_by_parent_group: data.access_by_parent_group,
			is_connected_group: data.is_connected_group,
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

#[repr(C)]
pub struct KeyRotationInput
{
	pub encrypted_ephemeral_key_by_group_key_and_public_key: String,
	pub encrypted_group_key_by_ephemeral: String,
	pub ephemeral_alg: String,
	pub encrypted_eph_key_key_id: String, //the public key id which was used to encrypt the eph key on the server.
	pub previous_group_key_id: String,
	pub time: String,
	pub new_group_key_id: String,
}

impl From<sentc_crypto_common::group::KeyRotationInput> for KeyRotationInput
{
	fn from(out: sentc_crypto_common::group::KeyRotationInput) -> Self
	{
		Self {
			encrypted_ephemeral_key_by_group_key_and_public_key: out.encrypted_ephemeral_key_by_group_key_and_public_key,
			encrypted_group_key_by_ephemeral: out.encrypted_group_key_by_ephemeral,
			ephemeral_alg: out.ephemeral_alg,
			encrypted_eph_key_key_id: out.encrypted_eph_key_key_id,
			previous_group_key_id: out.previous_group_key_id,
			time: out.time.to_string(),
			new_group_key_id: out.new_group_key_id,
		}
	}
}

//__________________________________________________________________________________________________

/**
Create input for the server api.

Use this for group and child group. For child group use the public key of the parent group!
 */
pub fn group_prepare_create_group(creators_public_key: String) -> Result<String>
{
	sentc_crypto::group::prepare_create(creators_public_key.as_str()).map_err(|err| anyhow!(err))
}

/**
Create a group with request.

Only the default values are send to the server, no extra data. If extra data is required, use prepare_create
 */
pub fn group_create_group(base_url: String, auth_token: String, jwt: String, creators_public_key: String, group_as_member: String) -> Result<String>
{
	rt(sentc_crypto_full::group::create(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		creators_public_key.as_str(),
		get_group_as_member(&group_as_member),
	))
}

pub fn group_create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_public_key: String,
	parent_id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<String>
{
	rt(sentc_crypto_full::group::create_child_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		parent_id.as_str(),
		admin_rank,
		parent_public_key.as_str(),
		get_group_as_member(&group_as_member),
	))
}

pub fn group_create_connected_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	connected_group_id: String,
	admin_rank: i32,
	parent_public_key: String,
	group_as_member: String,
) -> Result<String>
{
	rt(sentc_crypto_full::group::create_connected_group(
		base_url,
		&auth_token,
		&jwt,
		&connected_group_id,
		admin_rank,
		&parent_public_key,
		get_group_as_member(&group_as_member),
	))
}

//__________________________________________________________________________________________________

/**
Get the group data without request.

Use the parent group private key when fetching child group data.
 */
pub fn group_extract_group_data(server_output: String) -> Result<GroupOutData>
{
	let out = sentc_crypto::group::get_group_data(server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

/**
Get keys from pagination.

Call the group route with the last fetched key time and the last fetched key id. Get both from the key data.
 */
pub fn group_extract_group_keys(server_output: String) -> Result<Vec<GroupOutDataKeys>>
{
	let out = sentc_crypto::group::get_group_keys_from_server_output(server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

pub fn group_get_group_data(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: String) -> Result<GroupOutData>
{
	let out = rt(sentc_crypto_full::group::get_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into())
}

pub fn group_get_group_keys(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_key_id: String,
	group_as_member: String,
) -> Result<Vec<GroupOutDataKeys>>
{
	let out = rt(sentc_crypto_full::group::get_group_keys(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_key_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

pub fn group_get_group_key(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	key_id: String,
	group_as_member: String,
) -> Result<GroupOutDataKeys>
{
	let out = rt(sentc_crypto_full::group::get_group_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		key_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into())
}

pub fn group_decrypt_key(private_key: String, server_key_data: String) -> Result<GroupKeyData>
{
	let out = sentc_crypto_full::group::decrypt_key(server_key_data.as_str(), private_key.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

pub fn group_decrypt_hmac_key(group_key: String, server_key_data: String) -> Result<String>
{
	sentc_crypto::group::decrypt_group_hmac_key(&group_key, &server_key_data).map_err(|err| anyhow!(err))
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
pub struct GroupDataCheckUpdateServerOutput
{
	pub key_update: bool,
	pub rank: i32,
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
	group_as_member: String,
) -> Result<Vec<GroupUserListItem>>
{
	let out = rt(sentc_crypto_full::group::get_member(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_get_group_updates(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: String,
) -> Result<GroupDataCheckUpdateServerOutput>
{
	let out = rt(sentc_crypto_full::group::get_group_updates(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(GroupDataCheckUpdateServerOutput {
		key_update: out.key_update,
		rank: out.rank,
	})
}

pub fn group_get_all_first_level_children(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: String,
) -> Result<Vec<GroupChildrenList>>
{
	let out = rt(sentc_crypto_full::group::get_all_first_level_children(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&last_fetched_time,
		&last_fetched_group_id,
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_get_groups_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: String,
) -> Result<Vec<ListGroups>>
{
	let out = rt(sentc_crypto_full::group::get_groups_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		get_group_as_member(&group_id),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________
//invite

/**
Prepare all group keys for a new member.

Use the group keys from get group data or get group keys fn as string array
 */
pub fn group_prepare_keys_for_new_member(
	user_public_key: String,
	group_keys: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
) -> Result<String>
{
	sentc_crypto::group::check_make_invite_req(admin_rank).map_err(|err| anyhow!(err))?;

	let key_session = key_count > 50;

	sentc_crypto::group::prepare_group_keys_for_new_member(user_public_key.as_str(), group_keys.as_str(), key_session, rank)
		.map_err(|err| anyhow!(err))
}

pub fn group_invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
) -> Result<String>
{
	let out = rt(sentc_crypto_full::group::invite_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		key_count,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		user_public_key.as_str(),
		group_keys.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

pub fn group_invite_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	auto_invite: bool,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::invite_user_session(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		session_id.as_str(),
		auto_invite,
		user_public_key.as_str(),
		group_keys.as_str(),
		get_group_as_member(&group_as_member),
	))
}

pub fn group_get_invites_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: String,
	group_as_member: String,
) -> Result<Vec<GroupInviteReqList>>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	let out = rt(sentc_crypto_full::group::get_invites_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_accept_invite(base_url: String, auth_token: String, jwt: String, id: String, group_id: String, group_as_member: String) -> Result<()>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	rt(sentc_crypto_full::group::accept_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_reject_invite(base_url: String, auth_token: String, jwt: String, id: String, group_id: String, group_as_member: String) -> Result<()>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	rt(sentc_crypto_full::group::reject_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
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
	group_as_member: String,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = rt(sentc_crypto_full::group::get_sent_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		None,
		None,
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_get_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: String,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = rt(sentc_crypto_full::group::get_sent_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		Some(&id),
		Some(admin_rank),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn group_delete_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	join_req_group_id: String,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		None,
		None,
		&join_req_group_id,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_delete_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	join_req_group_id: String,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&join_req_group_id,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_join_req(base_url: String, auth_token: String, jwt: String, id: String, group_id: String, group_as_member: String) -> Result<()>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	rt(sentc_crypto_full::group::join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_get_join_reqs(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: String,
) -> Result<Vec<GroupJoinReqList>>
{
	let out = rt(sentc_crypto_full::group::get_join_reqs(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
		get_group_as_member(&group_as_member),
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
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::reject_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		rejected_user_id.as_str(),
		get_group_as_member(&group_as_member),
	))
}

pub fn group_accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
) -> Result<String>
{
	let out = rt(sentc_crypto_full::group::accept_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		key_count,
		rank,
		admin_rank,
		user_public_key.as_str(),
		group_keys.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

pub fn group_join_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
) -> Result<()>
{
	rt(async {
		sentc_crypto_full::group::join_user_session(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			id.as_str(),
			session_id.as_str(),
			user_public_key.as_str(),
			group_keys.as_str(),
			get_group_as_member(&group_as_member),
		)
		.await
	})
}

pub fn group_stop_group_invites(base_url: String, auth_token: String, jwt: String, id: String, admin_rank: i32, group_as_member: String)
	-> Result<()>
{
	rt(sentc_crypto_full::group::stop_group_invites(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	))
}

//__________________________________________________________________________________________________

pub fn leave_group(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: String) -> Result<()>
{
	rt(sentc_crypto_full::group::leave_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	))
}

//__________________________________________________________________________________________________
//key rotation

pub fn group_prepare_key_rotation(pre_group_key: String, public_key: String) -> Result<String>
{
	sentc_crypto::group::key_rotation(pre_group_key.as_str(), public_key.as_str(), false).map_err(|err| anyhow!(err))
}

pub fn group_done_key_rotation(private_key: String, public_key: String, pre_group_key: String, server_output: String) -> Result<String>
{
	sentc_crypto::group::done_key_rotation(
		private_key.as_str(),
		public_key.as_str(),
		pre_group_key.as_str(),
		server_output.as_str(),
	)
	.map_err(|err| anyhow!(err))
}

pub fn group_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	public_key: String,
	pre_group_key: String,
	group_as_member: String,
) -> Result<String>
{
	rt(sentc_crypto_full::group::key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		public_key.as_str(),
		pre_group_key.as_str(),
		false,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_pre_done_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: String,
) -> Result<Vec<KeyRotationGetOut>>
{
	let out = rt(sentc_crypto_full::group::prepare_done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		false,
		get_group_as_member(&group_as_member),
	))?;

	let mut list = Vec::with_capacity(out.len());

	for item in out {
		list.push(KeyRotationGetOut {
			pre_group_key_id: item.pre_group_key_id,
			new_group_key_id: item.new_group_key_id,
			encrypted_eph_key_key_id: item.encrypted_eph_key_key_id,
			server_output: item.server_output,
		});
	}

	Ok(list)
}

pub fn group_get_done_key_rotation_server_input(server_output: String) -> Result<KeyRotationInput>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

pub fn group_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		server_output.as_str(),
		pre_group_key.as_str(),
		public_key.as_str(),
		private_key.as_str(),
		false,
		get_group_as_member(&group_as_member),
	))
}

//__________________________________________________________________________________________________
//group update fn

pub fn group_prepare_update_rank(user_id: String, rank: i32, admin_rank: i32) -> Result<String>
{
	sentc_crypto::group::prepare_change_rank(user_id.as_str(), rank, admin_rank).map_err(|err| anyhow!(err))
}

pub fn group_update_rank(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::update_rank(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_kick_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<()>
{
	rt(sentc_crypto_full::group::kick_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	))
}

//__________________________________________________________________________________________________

pub fn group_delete_group(base_url: String, auth_token: String, jwt: String, id: String, admin_rank: i32, group_as_member: String) -> Result<()>
{
	rt(sentc_crypto_full::group::delete_group(
		//
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	))
}

pub fn group_get_public_key_data(base_url: String, auth_token: String, id: String) -> Result<UserPublicKeyData>
{
	let (public_key, public_key_id) = rt(sentc_crypto_full::group::get_public_key_data(
		base_url,
		auth_token.as_str(),
		&id,
	))?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
	})
}

//==================================================================================================
//crypto

#[repr(C)]
pub struct SignHead
{
	pub id: String,
	pub alg: String,
}

impl From<sentc_crypto_common::crypto::SignHead> for SignHead
{
	fn from(head: sentc_crypto_common::crypto::SignHead) -> Self
	{
		Self {
			id: head.id,
			alg: head.alg,
		}
	}
}

#[repr(C)]
pub struct EncryptedHead
{
	pub id: String,
	pub sign: Option<SignHead>,
}

#[repr(C)]
pub struct CryptoRawOutput
{
	pub head: String,
	pub data: Vec<u8>,
}

impl From<sentc_crypto_common::crypto::EncryptedHead> for EncryptedHead
{
	fn from(head: sentc_crypto_common::crypto::EncryptedHead) -> Self
	{
		let sign = match head.sign {
			Some(s) => Some(s.into()),
			None => None,
		};

		Self {
			id: head.id,
			sign,
		}
	}
}

pub fn split_head_and_encrypted_data(data: Vec<u8>) -> Result<EncryptedHead>
{
	let (head, _data) = sentc_crypto::crypto::split_head_and_encrypted_data(&data).map_err(|err| anyhow!(err))?;

	Ok(head.into())
}

pub fn split_head_and_encrypted_string(data: String) -> Result<EncryptedHead>
{
	let head = sentc_crypto::crypto::split_head_and_encrypted_string(&data).map_err(|err| anyhow!(err))?;

	Ok(head.into())
}

pub fn deserialize_head_from_string(head: String) -> Result<EncryptedHead>
{
	let head = sentc_crypto::crypto::deserialize_head_from_string(&head).map_err(|err| anyhow!(err))?;

	Ok(head.into())
}

pub fn encrypt_raw_symmetric(key: String, data: Vec<u8>, sign_key: String) -> Result<CryptoRawOutput>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_symmetric(key.as_str(), &data, &sign_key).map_err(|err| anyhow!(err))?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

pub fn decrypt_raw_symmetric(key: String, encrypted_data: Vec<u8>, head: String, verify_key_data: String) -> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::decrypt_raw_symmetric(key.as_str(), &encrypted_data, &head, &verify_key_data).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn encrypt_symmetric(key: String, data: Vec<u8>, sign_key: String) -> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::encrypt_symmetric(&key, &data, &sign_key).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn decrypt_symmetric(key: String, encrypted_data: Vec<u8>, verify_key_data: String) -> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::decrypt_symmetric(&key, &encrypted_data, &verify_key_data).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn encrypt_string_symmetric(key: String, data: String, sign_key: String) -> Result<String>
{
	sentc_crypto::crypto::encrypt_string_symmetric(&key, &data, &sign_key).map_err(|err| anyhow!(err))
}

pub fn decrypt_string_symmetric(key: String, encrypted_data: String, verify_key_data: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_string_symmetric(&key, &encrypted_data, &verify_key_data).map_err(|err| anyhow!(err))
}

pub fn encrypt_raw_asymmetric(reply_public_key_data: String, data: Vec<u8>, sign_key: String) -> Result<CryptoRawOutput>
{
	let (head, data) = sentc_crypto::crypto::encrypt_raw_asymmetric(&reply_public_key_data, &data, &sign_key).map_err(|err| anyhow!(err))?;

	Ok(CryptoRawOutput {
		head,
		data,
	})
}

pub fn decrypt_raw_asymmetric(private_key: String, encrypted_data: Vec<u8>, head: String, verify_key_data: String)
	-> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::decrypt_raw_asymmetric(&private_key, &encrypted_data, &head, &verify_key_data).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn encrypt_asymmetric(reply_public_key_data: String, data: Vec<u8>, sign_key: String) -> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::encrypt_asymmetric(&reply_public_key_data, &data, &sign_key).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn decrypt_asymmetric(private_key: String, encrypted_data: Vec<u8>, verify_key_data: String) -> Result<ZeroCopyBuffer<Vec<u8>>>
{
	let vec = sentc_crypto::crypto::decrypt_asymmetric(&private_key, &encrypted_data, &verify_key_data).map_err(|err| anyhow!(err))?;

	Ok(ZeroCopyBuffer(vec))
}

pub fn encrypt_string_asymmetric(reply_public_key_data: String, data: String, sign_key: String) -> Result<String>
{
	sentc_crypto::crypto::encrypt_string_asymmetric(&reply_public_key_data, &data, &sign_key).map_err(|err| anyhow!(err))
}

pub fn decrypt_string_asymmetric(private_key: String, encrypted_data: String, verify_key_data: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_string_asymmetric(&private_key, &encrypted_data, &verify_key_data).map_err(|err| anyhow!(err))
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct NonRegisteredKeyOutput
{
	pub key: String,
	pub encrypted_key: String,
}

pub fn generate_non_register_sym_key(master_key: String) -> Result<NonRegisteredKeyOutput>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key(&master_key).map_err(|err| anyhow!(err))?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

pub fn generate_non_register_sym_key_by_public_key(reply_public_key: String) -> Result<NonRegisteredKeyOutput>
{
	let (key, encrypted_key) = sentc_crypto::crypto::generate_non_register_sym_key_by_public_key(&reply_public_key).map_err(|err| anyhow!(err))?;

	Ok(NonRegisteredKeyOutput {
		key,
		encrypted_key,
	})
}

pub fn decrypt_sym_key(master_key: String, encrypted_symmetric_key_info: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_sym_key(&master_key, &encrypted_symmetric_key_info).map_err(|err| anyhow!(err))
}

pub fn decrypt_sym_key_by_private_key(private_key: String, encrypted_symmetric_key_info: String) -> Result<String>
{
	sentc_crypto::crypto::decrypt_sym_key_by_private_key(&private_key, &encrypted_symmetric_key_info).map_err(|err| anyhow!(err))
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct KeyGenOutput
{
	pub key: String,
	pub key_id: String,
}

pub fn generate_and_register_sym_key(base_url: String, auth_token: String, jwt: String, master_key: String) -> Result<KeyGenOutput>
{
	let (key_id, key) = rt(sentc_crypto_full::crypto::register_sym_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		master_key.as_str(),
	))?;

	Ok(KeyGenOutput {
		key,
		key_id,
	})
}

pub fn generate_and_register_sym_key_by_public_key(base_url: String, auth_token: String, jwt: String, public_key: String) -> Result<KeyGenOutput>
{
	let (key_id, key) = rt(sentc_crypto_full::crypto::register_key_by_public_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		public_key.as_str(),
	))?;

	Ok(KeyGenOutput {
		key,
		key_id,
	})
}

pub fn get_sym_key_by_id(base_url: String, auth_token: String, key_id: String, master_key: String) -> Result<String>
{
	rt(sentc_crypto_full::crypto::get_sym_key_by_id(
		base_url,
		auth_token.as_str(),
		key_id.as_str(),
		master_key.as_str(),
	))
}

pub fn get_sym_key_by_id_by_private_key(base_url: String, auth_token: String, key_id: String, private_key: String) -> Result<String>
{
	rt(sentc_crypto_full::crypto::get_sym_key_by_id_by_private_key(
		base_url,
		auth_token.as_str(),
		key_id.as_str(),
		private_key.as_str(),
	))
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct KeysToMasterKeyFetch
{
	pub last_fetched_time: String,
	pub last_key_id: String,
	pub keys: Vec<String>,
}

pub fn get_keys_for_master_key(
	base_url: String,
	auth_token: String,
	master_key_id: String,
	last_fetched_time: String,
	last_key_id: String,
	master_key: String,
) -> Result<KeysToMasterKeyFetch>
{
	let (keys, last_fetched_time, last_key_id) = rt(sentc_crypto_full::crypto::get_keys_for_master_key(
		base_url,
		auth_token.as_str(),
		master_key_id.as_str(),
		last_fetched_time.as_str(),
		last_key_id.as_str(),
		master_key.as_str(),
	))?;

	Ok(KeysToMasterKeyFetch {
		last_fetched_time: last_fetched_time.to_string(),
		last_key_id,
		keys,
	})
}

pub fn delete_sym_key(base_url: String, auth_token: String, jwt: String, key_id: String) -> Result<()>
{
	rt(sentc_crypto_full::crypto::delete_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		key_id.as_str(),
	))
}

//__________________________________________________________________________________________________
//searchable crypto
#[repr(C)]
pub struct ListSearchItem
{
	pub id: String,
	pub item_ref: String,
	pub time: String,
}

impl From<sentc_crypto_common::content_searchable::ListSearchItem> for ListSearchItem
{
	fn from(item: sentc_crypto_common::content_searchable::ListSearchItem) -> Self
	{
		Self {
			id: item.id,
			item_ref: item.item_ref,
			time: item.time.to_string(),
		}
	}
}

#[repr(C)]
pub struct SearchCreateDataLight
{
	pub hashes: Vec<String>,
	pub alg: String,
	pub key_id: String,
}

impl From<sentc_crypto_common::content_searchable::SearchCreateDataLight> for SearchCreateDataLight
{
	fn from(value: sentc_crypto_common::content_searchable::SearchCreateDataLight) -> Self
	{
		Self {
			hashes: value.hashes,
			alg: value.alg,
			key_id: value.key_id,
		}
	}
}

pub fn prepare_create_searchable(key: String, item_ref: String, category: String, data: String, full: bool, limit: Option<u32>) -> Result<String>
{
	//flutter rust bridge don't support usize
	let limit = if let Some(l) = limit { Some(l as usize) } else { None };

	sentc_crypto::crypto_searchable::create_searchable(&key, &item_ref, &category, &data, full, limit).map_err(|err| anyhow!(err))
}

pub fn prepare_create_searchable_light(key: String, data: String, full: bool, limit: Option<u32>) -> Result<SearchCreateDataLight>
{
	//flutter rust bridge don't support usize
	let limit = if let Some(l) = limit { Some(l as usize) } else { None };

	let out = sentc_crypto::crypto_searchable::prepare_create_searchable_light(&key, &data, full, limit).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

pub fn prepare_search(key: String, data: String) -> Result<String>
{
	sentc_crypto::crypto_searchable::search(&key, &data).map_err(|err| anyhow!(err))
}

pub fn search(
	base_url: String,
	auth_token: String,
	jwt: String,
	group_id: String,
	group_as_member: String,
	key: String,
	data: String,
	cat_id: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
) -> Result<Vec<ListSearchItem>>
{
	let cat_id = if cat_id.is_empty() { None } else { Some(cat_id.as_str()) };

	let out = rt(sentc_crypto_full::crypto::search(
		base_url,
		&auth_token,
		&jwt,
		&group_id,
		get_group_as_member(&group_as_member),
		cat_id,
		&key,
		&data,
		&last_fetched_time,
		&last_fetched_group_id,
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//==================================================================================================
//file

#[repr(C)]
pub enum BelongsToType
{
	Group,
	User,
	None,
}

impl From<sentc_crypto_common::file::BelongsToType> for BelongsToType
{
	fn from(t: sentc_crypto_common::file::BelongsToType) -> Self
	{
		match t {
			sentc_crypto_common::file::BelongsToType::None => Self::None,
			sentc_crypto_common::file::BelongsToType::Group => Self::Group,
			sentc_crypto_common::file::BelongsToType::User => Self::User,
		}
	}
}

#[repr(C)]
pub struct FilePartListItem
{
	pub part_id: String,
	pub sequence: i32,
	pub extern_storage: bool,
}

impl From<sentc_crypto_common::file::FilePartListItem> for FilePartListItem
{
	fn from(item: sentc_crypto_common::file::FilePartListItem) -> Self
	{
		Self {
			part_id: item.part_id,
			sequence: item.sequence,
			extern_storage: item.extern_storage,
		}
	}
}

#[repr(C)]
pub struct FileData
{
	pub file_id: String,
	pub master_key_id: String,
	pub owner: String,
	pub belongs_to: Option<String>, //can be a group or a user. if belongs to type is none then this is Option::None
	pub belongs_to_type: BelongsToType,
	pub key_id: String,
	pub encrypted_file_name: Option<String>,
	pub part_list: Vec<FilePartListItem>,
}

impl From<sentc_crypto_common::file::FileData> for FileData
{
	fn from(data: sentc_crypto_common::file::FileData) -> Self
	{
		Self {
			file_id: data.file_id,
			master_key_id: data.master_key_id,
			owner: data.owner,
			belongs_to: data.belongs_to,
			belongs_to_type: data.belongs_to_type.into(),
			key_id: data.key_id,
			encrypted_file_name: data.encrypted_file_name,
			part_list: data.part_list.into_iter().map(|part| part.into()).collect(),
		}
	}
}

pub fn file_download_file_meta(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: String,
) -> Result<FileData>
{
	let out = rt(sentc_crypto_full::file::download_file_meta(
		base_url,
		auth_token.as_str(),
		id.as_str(),
		jwt.as_str(),
		group_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(out.into())
}

#[repr(C)]
pub struct FileDownloadResult
{
	pub next_file_key: String,
	pub file: ZeroCopyBuffer<Vec<u8>>,
}

pub fn file_download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: String,
) -> Result<FileDownloadResult>
{
	let (file, next_file_key) = rt(sentc_crypto_full::file::download_and_decrypt_file_part_start(
		base_url,
		url_prefix,
		auth_token.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_str(),
	))?;

	Ok(FileDownloadResult {
		next_file_key,
		file: ZeroCopyBuffer(file),
	})
}

pub fn file_download_and_decrypt_file_part(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	part_id: String,
	content_key: String,
	verify_key_data: String,
) -> Result<FileDownloadResult>
{
	let (file, next_file_key) = rt(sentc_crypto_full::file::download_and_decrypt_file_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		part_id.as_str(),
		content_key.as_str(),
		verify_key_data.as_str(),
	))?;

	Ok(FileDownloadResult {
		next_file_key,
		file: ZeroCopyBuffer(file),
	})
}

pub fn file_download_part_list(base_url: String, auth_token: String, file_id: String, last_sequence: String) -> Result<Vec<FilePartListItem>>
{
	let out = rt(sentc_crypto_full::file::download_part_list(
		base_url,
		auth_token.as_str(),
		file_id.as_str(),
		last_sequence.as_str(),
	))?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct FileRegisterOutput
{
	pub file_id: String,
	pub session_id: String,
	pub encrypted_file_name: String,
}

#[repr(C)]
pub struct FilePrepareRegister
{
	pub encrypted_file_name: String,
	pub server_input: String,
}

#[repr(C)]
pub struct FileDoneRegister
{
	pub file_id: String,
	pub session_id: String,
}

pub fn file_register_file(
	base_url: String,
	auth_token: String,
	jwt: String,
	master_key_id: String,
	content_key: String,
	belongs_to_id: String,
	belongs_to_type: String,
	file_name: String,
	group_id: String,
	group_as_member: String,
) -> Result<FileRegisterOutput>
{
	let (file_id, session_id, encrypted_file_name) = rt(sentc_crypto_full::file::register_file(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		master_key_id,
		content_key.as_str(),
		belongs_to_id.as_str(),
		belongs_to_type.as_str(),
		file_name.as_str(),
		group_id.as_str(),
		get_group_as_member(&group_as_member),
	))?;

	Ok(FileRegisterOutput {
		file_id,
		session_id,
		encrypted_file_name,
	})
}

pub fn file_prepare_register_file(
	master_key_id: String,
	content_key: String,
	belongs_to_id: String,
	belongs_to_type: String,
	file_name: String,
) -> Result<FilePrepareRegister>
{
	let (input, encrypted_file_name) = sentc_crypto::file::prepare_register_file(
		master_key_id,
		&content_key,
		&belongs_to_id,
		&belongs_to_type,
		&file_name,
	)
	.map_err(|err| anyhow!(err))?;

	Ok(FilePrepareRegister {
		encrypted_file_name,
		server_input: input,
	})
}

pub fn file_done_register_file(server_output: String) -> Result<FileDoneRegister>
{
	let (file_id, session_id) = sentc_crypto::file::done_register_file(&server_output).map_err(|err| anyhow!(err))?;

	Ok(FileDoneRegister {
		file_id,
		session_id,
	})
}

pub fn file_upload_part_start(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	sequence: i32,
	content_key: String,
	sign_key: String,
	part: Vec<u8>,
) -> Result<String>
{
	rt(sentc_crypto_full::file::upload_part_start(
		base_url,
		url_prefix,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		sequence,
		content_key.as_str(),
		sign_key.as_str(),
		&part,
	))
}

pub fn file_upload_part(
	base_url: String,
	url_prefix: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	end: bool,
	sequence: i32,
	content_key: String,
	sign_key: String,
	part: Vec<u8>,
) -> Result<String>
{
	rt(sentc_crypto_full::file::upload_part(
		base_url,
		url_prefix,
		auth_token.as_str(),
		jwt.as_str(),
		session_id.as_str(),
		end,
		sequence,
		content_key.as_str(),
		sign_key.as_str(),
		&part,
	))
}

pub fn file_file_name_update(base_url: String, auth_token: String, jwt: String, file_id: String, content_key: String, file_name: String)
	-> Result<()>
{
	rt(sentc_crypto_full::file::update_file_name(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		file_id.as_str(),
		content_key.as_str(),
		file_name.as_str(),
	))
}

pub fn file_delete_file(base_url: String, auth_token: String, jwt: String, file_id: String, group_id: String, group_as_member: String) -> Result<()>
{
	rt(sentc_crypto_full::file::delete_file(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		file_id.as_str(),
		group_id.as_str(),
		get_group_as_member(&group_as_member),
	))
}

#[inline(never)]
fn get_group_as_member(group_as_member: &String) -> Option<&str>
{
	if group_as_member.is_empty() {
		None
	} else {
		Some(group_as_member.as_str())
	}
}
