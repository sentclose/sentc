use super::*;
// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_decode_jwt(port_: i64, jwt: *mut wire_uint_8_list) {
	wire_decode_jwt_impl(port_, jwt)
}

#[no_mangle]
pub extern "C" fn wire_check_user_identifier_available(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
) {
	wire_check_user_identifier_available_impl(port_, base_url, auth_token, user_identifier)
}

#[no_mangle]
pub extern "C" fn wire_prepare_check_user_identifier_available(port_: i64, user_identifier: *mut wire_uint_8_list) {
	wire_prepare_check_user_identifier_available_impl(port_, user_identifier)
}

#[no_mangle]
pub extern "C" fn wire_done_check_user_identifier_available(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_done_check_user_identifier_available_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_generate_user_register_data(port_: i64) {
	wire_generate_user_register_data_impl(port_)
}

#[no_mangle]
pub extern "C" fn wire_prepare_register(port_: i64, user_identifier: *mut wire_uint_8_list, password: *mut wire_uint_8_list) {
	wire_prepare_register_impl(port_, user_identifier, password)
}

#[no_mangle]
pub extern "C" fn wire_done_register(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_done_register_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_register(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
	password: *mut wire_uint_8_list,
) {
	wire_register_impl(port_, base_url, auth_token, user_identifier, password)
}

#[no_mangle]
pub extern "C" fn wire_prepare_register_device_start(port_: i64, device_identifier: *mut wire_uint_8_list, password: *mut wire_uint_8_list) {
	wire_prepare_register_device_start_impl(port_, device_identifier, password)
}

#[no_mangle]
pub extern "C" fn wire_done_register_device_start(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_done_register_device_start_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_register_device_start(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	device_identifier: *mut wire_uint_8_list,
	password: *mut wire_uint_8_list,
) {
	wire_register_device_start_impl(port_, base_url, auth_token, device_identifier, password)
}

#[no_mangle]
pub extern "C" fn wire_prepare_register_device(port_: i64, server_output: *mut wire_uint_8_list, user_keys: *mut wire_uint_8_list, key_count: i32) {
	wire_prepare_register_device_impl(port_, server_output, user_keys, key_count)
}

#[no_mangle]
pub extern "C" fn wire_register_device(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	server_output: *mut wire_uint_8_list,
	key_count: i32,
	user_keys: *mut wire_uint_8_list,
) {
	wire_register_device_impl(port_, base_url, auth_token, jwt, server_output, key_count, user_keys)
}

#[no_mangle]
pub extern "C" fn wire_user_device_key_session_upload(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	session_id: *mut wire_uint_8_list,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
) {
	wire_user_device_key_session_upload_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		session_id,
		user_public_key,
		group_keys,
	)
}

#[no_mangle]
pub extern "C" fn wire_login(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
	password: *mut wire_uint_8_list,
) {
	wire_login_impl(port_, base_url, auth_token, user_identifier, password)
}

#[no_mangle]
pub extern "C" fn wire_mfa_login(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	master_key_encryption: *mut wire_uint_8_list,
	auth_key: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
	token: *mut wire_uint_8_list,
	recovery: bool,
) {
	wire_mfa_login_impl(
		port_,
		base_url,
		auth_token,
		master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	)
}

#[no_mangle]
pub extern "C" fn wire_done_fetch_user_key(port_: i64, private_key: *mut wire_uint_8_list, server_output: *mut wire_uint_8_list) {
	wire_done_fetch_user_key_impl(port_, private_key, server_output)
}

#[no_mangle]
pub extern "C" fn wire_fetch_user_key(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	key_id: *mut wire_uint_8_list,
	private_key: *mut wire_uint_8_list,
) {
	wire_fetch_user_key_impl(port_, base_url, auth_token, jwt, key_id, private_key)
}

#[no_mangle]
pub extern "C" fn wire_get_fresh_jwt(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
	password: *mut wire_uint_8_list,
	mfa_token: *mut wire_uint_8_list,
	mfa_recovery: *mut bool,
) {
	wire_get_fresh_jwt_impl(
		port_,
		base_url,
		auth_token,
		user_identifier,
		password,
		mfa_token,
		mfa_recovery,
	)
}

#[no_mangle]
pub extern "C" fn wire_refresh_jwt(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	refresh_token: *mut wire_uint_8_list,
) {
	wire_refresh_jwt_impl(port_, base_url, auth_token, jwt, refresh_token)
}

#[no_mangle]
pub extern "C" fn wire_init_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	refresh_token: *mut wire_uint_8_list,
) {
	wire_init_user_impl(port_, base_url, auth_token, jwt, refresh_token)
}

#[no_mangle]
pub extern "C" fn wire_user_create_safety_number(
	port_: i64,
	verify_key_1: *mut wire_uint_8_list,
	user_id_1: *mut wire_uint_8_list,
	verify_key_2: *mut wire_uint_8_list,
	user_id_2: *mut wire_uint_8_list,
) {
	wire_user_create_safety_number_impl(port_, verify_key_1, user_id_1, verify_key_2, user_id_2)
}

#[no_mangle]
pub extern "C" fn wire_user_verify_user_public_key(port_: i64, verify_key: *mut wire_uint_8_list, public_key: *mut wire_uint_8_list) {
	wire_user_verify_user_public_key_impl(port_, verify_key, public_key)
}

#[no_mangle]
pub extern "C" fn wire_get_user_devices(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_id: *mut wire_uint_8_list,
) {
	wire_get_user_devices_impl(port_, base_url, auth_token, jwt, last_fetched_time, last_fetched_id)
}

#[no_mangle]
pub extern "C" fn wire_reset_password(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	new_password: *mut wire_uint_8_list,
	decrypted_private_key: *mut wire_uint_8_list,
	decrypted_sign_key: *mut wire_uint_8_list,
) {
	wire_reset_password_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		new_password,
		decrypted_private_key,
		decrypted_sign_key,
	)
}

#[no_mangle]
pub extern "C" fn wire_change_password(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
	old_password: *mut wire_uint_8_list,
	new_password: *mut wire_uint_8_list,
	mfa_token: *mut wire_uint_8_list,
	mfa_recovery: *mut bool,
) {
	wire_change_password_impl(
		port_,
		base_url,
		auth_token,
		user_identifier,
		old_password,
		new_password,
		mfa_token,
		mfa_recovery,
	)
}

#[no_mangle]
pub extern "C" fn wire_delete_user(port_: i64, base_url: *mut wire_uint_8_list, auth_token: *mut wire_uint_8_list, fresh_jwt: *mut wire_uint_8_list) {
	wire_delete_user_impl(port_, base_url, auth_token, fresh_jwt)
}

#[no_mangle]
pub extern "C" fn wire_delete_device(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	fresh_jwt: *mut wire_uint_8_list,
	device_id: *mut wire_uint_8_list,
) {
	wire_delete_device_impl(port_, base_url, auth_token, fresh_jwt, device_id)
}

#[no_mangle]
pub extern "C" fn wire_update_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	user_identifier: *mut wire_uint_8_list,
) {
	wire_update_user_impl(port_, base_url, auth_token, jwt, user_identifier)
}

#[no_mangle]
pub extern "C" fn wire_user_fetch_public_key(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
) {
	wire_user_fetch_public_key_impl(port_, base_url, auth_token, user_id)
}

#[no_mangle]
pub extern "C" fn wire_user_fetch_verify_key(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	verify_key_id: *mut wire_uint_8_list,
) {
	wire_user_fetch_verify_key_impl(port_, base_url, auth_token, user_id, verify_key_id)
}

#[no_mangle]
pub extern "C" fn wire_user_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	public_device_key: *mut wire_uint_8_list,
	pre_user_key: *mut wire_uint_8_list,
) {
	wire_user_key_rotation_impl(port_, base_url, auth_token, jwt, public_device_key, pre_user_key)
}

#[no_mangle]
pub extern "C" fn wire_user_pre_done_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
) {
	wire_user_pre_done_key_rotation_impl(port_, base_url, auth_token, jwt)
}

#[no_mangle]
pub extern "C" fn wire_user_get_done_key_rotation_server_input(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_user_get_done_key_rotation_server_input_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_user_finish_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	server_output: *mut wire_uint_8_list,
	pre_group_key: *mut wire_uint_8_list,
	public_key: *mut wire_uint_8_list,
	private_key: *mut wire_uint_8_list,
) {
	wire_user_finish_key_rotation_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		server_output,
		pre_group_key,
		public_key,
		private_key,
	)
}

#[no_mangle]
pub extern "C" fn wire_register_raw_otp(port_: i64, base_url: *mut wire_uint_8_list, auth_token: *mut wire_uint_8_list, jwt: *mut wire_uint_8_list) {
	wire_register_raw_otp_impl(port_, base_url, auth_token, jwt)
}

#[no_mangle]
pub extern "C" fn wire_register_otp(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	issuer: *mut wire_uint_8_list,
	audience: *mut wire_uint_8_list,
) {
	wire_register_otp_impl(port_, base_url, auth_token, jwt, issuer, audience)
}

#[no_mangle]
pub extern "C" fn wire_get_otp_recover_keys(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
) {
	wire_get_otp_recover_keys_impl(port_, base_url, auth_token, jwt)
}

#[no_mangle]
pub extern "C" fn wire_reset_raw_otp(port_: i64, base_url: *mut wire_uint_8_list, auth_token: *mut wire_uint_8_list, jwt: *mut wire_uint_8_list) {
	wire_reset_raw_otp_impl(port_, base_url, auth_token, jwt)
}

#[no_mangle]
pub extern "C" fn wire_reset_otp(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	issuer: *mut wire_uint_8_list,
	audience: *mut wire_uint_8_list,
) {
	wire_reset_otp_impl(port_, base_url, auth_token, jwt, issuer, audience)
}

#[no_mangle]
pub extern "C" fn wire_disable_otp(port_: i64, base_url: *mut wire_uint_8_list, auth_token: *mut wire_uint_8_list, jwt: *mut wire_uint_8_list) {
	wire_disable_otp_impl(port_, base_url, auth_token, jwt)
}

#[no_mangle]
pub extern "C" fn wire_group_prepare_create_group(
	port_: i64,
	creators_public_key: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
) {
	wire_group_prepare_create_group_impl(port_, creators_public_key, sign_key, starter)
}

#[no_mangle]
pub extern "C" fn wire_group_create_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	creators_public_key: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
) {
	wire_group_create_group_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		creators_public_key,
		group_as_member,
		sign_key,
		starter,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_create_child_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	parent_public_key: *mut wire_uint_8_list,
	parent_id: *mut wire_uint_8_list,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
) {
	wire_group_create_child_group_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		parent_public_key,
		parent_id,
		admin_rank,
		group_as_member,
		sign_key,
		starter,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_create_connected_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	connected_group_id: *mut wire_uint_8_list,
	admin_rank: i32,
	parent_public_key: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
) {
	wire_group_create_connected_group_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		connected_group_id,
		admin_rank,
		parent_public_key,
		group_as_member,
		sign_key,
		starter,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_extract_group_data(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_group_extract_group_data_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_group_extract_group_keys(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_group_extract_group_keys_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_group_get_group_data(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_group_data_impl(port_, base_url, auth_token, jwt, id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_group_keys(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_key_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_group_keys_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_key_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_get_group_key(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	key_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_group_key_impl(port_, base_url, auth_token, jwt, id, key_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_decrypt_key(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	server_key_data: *mut wire_uint_8_list,
	verify_key: *mut wire_uint_8_list,
) {
	wire_group_decrypt_key_impl(port_, private_key, server_key_data, verify_key)
}

#[no_mangle]
pub extern "C" fn wire_group_decrypt_hmac_key(port_: i64, group_key: *mut wire_uint_8_list, server_key_data: *mut wire_uint_8_list) {
	wire_group_decrypt_hmac_key_impl(port_, group_key, server_key_data)
}

#[no_mangle]
pub extern "C" fn wire_group_decrypt_sortable_key(port_: i64, group_key: *mut wire_uint_8_list, server_key_data: *mut wire_uint_8_list) {
	wire_group_decrypt_sortable_key_impl(port_, group_key, server_key_data)
}

#[no_mangle]
pub extern "C" fn wire_group_get_member(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_member_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_get_group_updates(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_group_updates_impl(port_, base_url, auth_token, jwt, id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_all_first_level_children(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_all_first_level_children_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_get_groups_for_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_group_id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
) {
	wire_group_get_groups_for_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		last_fetched_time,
		last_fetched_group_id,
		group_id,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_prepare_keys_for_new_member(
	port_: i64,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
	key_count: i32,
	rank: *mut i32,
	admin_rank: i32,
) {
	wire_group_prepare_keys_for_new_member_impl(port_, user_public_key, group_keys, key_count, rank, admin_rank)
}

#[no_mangle]
pub extern "C" fn wire_group_invite_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	key_count: i32,
	rank: *mut i32,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	re_invite: bool,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_invite_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		key_count,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		re_invite,
		user_public_key,
		group_keys,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_invite_user_session(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	auto_invite: bool,
	session_id: *mut wire_uint_8_list,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_invite_user_session_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		auto_invite,
		session_id,
		user_public_key,
		group_keys,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_get_invites_for_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_group_id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_invites_for_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		last_fetched_time,
		last_fetched_group_id,
		group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_accept_invite(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_accept_invite_impl(port_, base_url, auth_token, jwt, id, group_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_reject_invite(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_reject_invite_impl(port_, base_url, auth_token, jwt, id, group_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_sent_join_req_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_sent_join_req_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		last_fetched_time,
		last_fetched_group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_get_sent_join_req(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_sent_join_req_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		last_fetched_time,
		last_fetched_group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_delete_sent_join_req_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	join_req_group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_delete_sent_join_req_user_impl(port_, base_url, auth_token, jwt, join_req_group_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_delete_sent_join_req(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	join_req_group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_delete_sent_join_req_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		join_req_group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_join_req(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_join_req_impl(port_, base_url, auth_token, jwt, id, group_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_join_reqs(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	last_fetched_time: *mut wire_uint_8_list,
	last_fetched_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_get_join_reqs_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		last_fetched_time,
		last_fetched_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_reject_join_req(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	rejected_user_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_reject_join_req_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		rejected_user_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_accept_join_req(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	key_count: i32,
	rank: *mut i32,
	admin_rank: i32,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_accept_join_req_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		key_count,
		rank,
		admin_rank,
		user_public_key,
		group_keys,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_join_user_session(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	session_id: *mut wire_uint_8_list,
	user_public_key: *mut wire_uint_8_list,
	group_keys: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_join_user_session_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		session_id,
		user_public_key,
		group_keys,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_stop_group_invites(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_stop_group_invites_impl(port_, base_url, auth_token, jwt, id, admin_rank, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_leave_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_leave_group_impl(port_, base_url, auth_token, jwt, id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_prepare_key_rotation(
	port_: i64,
	pre_group_key: *mut wire_uint_8_list,
	public_key: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
) {
	wire_group_prepare_key_rotation_impl(port_, pre_group_key, public_key, sign_key, starter)
}

#[no_mangle]
pub extern "C" fn wire_group_done_key_rotation(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	public_key: *mut wire_uint_8_list,
	pre_group_key: *mut wire_uint_8_list,
	server_output: *mut wire_uint_8_list,
) {
	wire_group_done_key_rotation_impl(port_, private_key, public_key, pre_group_key, server_output)
}

#[no_mangle]
pub extern "C" fn wire_group_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	public_key: *mut wire_uint_8_list,
	pre_group_key: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	starter: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_key_rotation_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		public_key,
		pre_group_key,
		sign_key,
		starter,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_pre_done_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_pre_done_key_rotation_impl(port_, base_url, auth_token, jwt, id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_done_key_rotation_server_input(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_group_get_done_key_rotation_server_input_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_group_finish_key_rotation(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	server_output: *mut wire_uint_8_list,
	pre_group_key: *mut wire_uint_8_list,
	public_key: *mut wire_uint_8_list,
	private_key: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_finish_key_rotation_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		server_output,
		pre_group_key,
		public_key,
		private_key,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_prepare_update_rank(port_: i64, user_id: *mut wire_uint_8_list, rank: i32, admin_rank: i32) {
	wire_group_prepare_update_rank_impl(port_, user_id, rank, admin_rank)
}

#[no_mangle]
pub extern "C" fn wire_group_update_rank(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	rank: i32,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_update_rank_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_kick_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_kick_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		admin_rank,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_delete_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_delete_group_impl(port_, base_url, auth_token, jwt, id, admin_rank, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_get_public_key_data(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
) {
	wire_group_get_public_key_data_impl(port_, base_url, auth_token, id)
}

#[no_mangle]
pub extern "C" fn wire_split_head_and_encrypted_data(port_: i64, data: *mut wire_uint_8_list) {
	wire_split_head_and_encrypted_data_impl(port_, data)
}

#[no_mangle]
pub extern "C" fn wire_split_head_and_encrypted_string(port_: i64, data: *mut wire_uint_8_list) {
	wire_split_head_and_encrypted_string_impl(port_, data)
}

#[no_mangle]
pub extern "C" fn wire_deserialize_head_from_string(port_: i64, head: *mut wire_uint_8_list) {
	wire_deserialize_head_from_string_impl(port_, head)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_raw_symmetric(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list, sign_key: *mut wire_uint_8_list) {
	wire_encrypt_raw_symmetric_impl(port_, key, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_raw_symmetric(
	port_: i64,
	key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	head: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_raw_symmetric_impl(port_, key, encrypted_data, head, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_symmetric(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list, sign_key: *mut wire_uint_8_list) {
	wire_encrypt_symmetric_impl(port_, key, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_symmetric(
	port_: i64,
	key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_symmetric_impl(port_, key, encrypted_data, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_string_symmetric(
	port_: i64,
	key: *mut wire_uint_8_list,
	data: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
) {
	wire_encrypt_string_symmetric_impl(port_, key, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_string_symmetric(
	port_: i64,
	key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_string_symmetric_impl(port_, key, encrypted_data, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_raw_asymmetric(
	port_: i64,
	reply_public_key_data: *mut wire_uint_8_list,
	data: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
) {
	wire_encrypt_raw_asymmetric_impl(port_, reply_public_key_data, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_raw_asymmetric(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	head: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_raw_asymmetric_impl(port_, private_key, encrypted_data, head, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_asymmetric(
	port_: i64,
	reply_public_key_data: *mut wire_uint_8_list,
	data: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
) {
	wire_encrypt_asymmetric_impl(port_, reply_public_key_data, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_asymmetric(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_asymmetric_impl(port_, private_key, encrypted_data, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_encrypt_string_asymmetric(
	port_: i64,
	reply_public_key_data: *mut wire_uint_8_list,
	data: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
) {
	wire_encrypt_string_asymmetric_impl(port_, reply_public_key_data, data, sign_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_string_asymmetric(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	encrypted_data: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_decrypt_string_asymmetric_impl(port_, private_key, encrypted_data, verify_key_data)
}

#[no_mangle]
pub extern "C" fn wire_generate_non_register_sym_key(port_: i64, master_key: *mut wire_uint_8_list) {
	wire_generate_non_register_sym_key_impl(port_, master_key)
}

#[no_mangle]
pub extern "C" fn wire_generate_non_register_sym_key_by_public_key(port_: i64, reply_public_key: *mut wire_uint_8_list) {
	wire_generate_non_register_sym_key_by_public_key_impl(port_, reply_public_key)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_sym_key(port_: i64, master_key: *mut wire_uint_8_list, encrypted_symmetric_key_info: *mut wire_uint_8_list) {
	wire_decrypt_sym_key_impl(port_, master_key, encrypted_symmetric_key_info)
}

#[no_mangle]
pub extern "C" fn wire_decrypt_sym_key_by_private_key(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	encrypted_symmetric_key_info: *mut wire_uint_8_list,
) {
	wire_decrypt_sym_key_by_private_key_impl(port_, private_key, encrypted_symmetric_key_info)
}

#[no_mangle]
pub extern "C" fn wire_done_fetch_sym_key(port_: i64, master_key: *mut wire_uint_8_list, server_out: *mut wire_uint_8_list, non_registered: bool) {
	wire_done_fetch_sym_key_impl(port_, master_key, server_out, non_registered)
}

#[no_mangle]
pub extern "C" fn wire_done_fetch_sym_key_by_private_key(
	port_: i64,
	private_key: *mut wire_uint_8_list,
	server_out: *mut wire_uint_8_list,
	non_registered: bool,
) {
	wire_done_fetch_sym_key_by_private_key_impl(port_, private_key, server_out, non_registered)
}

#[no_mangle]
pub extern "C" fn wire_create_searchable_raw(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list, full: bool, limit: *mut u32) {
	wire_create_searchable_raw_impl(port_, key, data, full, limit)
}

#[no_mangle]
pub extern "C" fn wire_create_searchable(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list, full: bool, limit: *mut u32) {
	wire_create_searchable_impl(port_, key, data, full, limit)
}

#[no_mangle]
pub extern "C" fn wire_search(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list) {
	wire_search_impl(port_, key, data)
}

#[no_mangle]
pub extern "C" fn wire_sortable_encrypt_raw_number(port_: i64, key: *mut wire_uint_8_list, data: u64) {
	wire_sortable_encrypt_raw_number_impl(port_, key, data)
}

#[no_mangle]
pub extern "C" fn wire_sortable_encrypt_number(port_: i64, key: *mut wire_uint_8_list, data: u64) {
	wire_sortable_encrypt_number_impl(port_, key, data)
}

#[no_mangle]
pub extern "C" fn wire_sortable_encrypt_raw_string(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list) {
	wire_sortable_encrypt_raw_string_impl(port_, key, data)
}

#[no_mangle]
pub extern "C" fn wire_sortable_encrypt_string(port_: i64, key: *mut wire_uint_8_list, data: *mut wire_uint_8_list) {
	wire_sortable_encrypt_string_impl(port_, key, data)
}

#[no_mangle]
pub extern "C" fn wire_file_download_file_meta(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_file_download_file_meta_impl(port_, base_url, auth_token, jwt, id, group_id, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_file_download_and_decrypt_file_part_start(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	url_prefix: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	part_id: *mut wire_uint_8_list,
	content_key: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_file_download_and_decrypt_file_part_start_impl(
		port_,
		base_url,
		url_prefix,
		auth_token,
		part_id,
		content_key,
		verify_key_data,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_download_and_decrypt_file_part(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	url_prefix: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	part_id: *mut wire_uint_8_list,
	content_key: *mut wire_uint_8_list,
	verify_key_data: *mut wire_uint_8_list,
) {
	wire_file_download_and_decrypt_file_part_impl(
		port_,
		base_url,
		url_prefix,
		auth_token,
		part_id,
		content_key,
		verify_key_data,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_download_part_list(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	file_id: *mut wire_uint_8_list,
	last_sequence: *mut wire_uint_8_list,
) {
	wire_file_download_part_list_impl(port_, base_url, auth_token, file_id, last_sequence)
}

#[no_mangle]
pub extern "C" fn wire_file_register_file(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	master_key_id: *mut wire_uint_8_list,
	content_key: *mut wire_uint_8_list,
	encrypted_content_key: *mut wire_uint_8_list,
	belongs_to_id: *mut wire_uint_8_list,
	belongs_to_type: *mut wire_uint_8_list,
	file_name: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_file_register_file_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		master_key_id,
		content_key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
		group_id,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_prepare_register_file(
	port_: i64,
	master_key_id: *mut wire_uint_8_list,
	content_key: *mut wire_uint_8_list,
	encrypted_content_key: *mut wire_uint_8_list,
	belongs_to_id: *mut wire_uint_8_list,
	belongs_to_type: *mut wire_uint_8_list,
	file_name: *mut wire_uint_8_list,
) {
	wire_file_prepare_register_file_impl(
		port_,
		master_key_id,
		content_key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_done_register_file(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_file_done_register_file_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_file_upload_part_start(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	url_prefix: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	session_id: *mut wire_uint_8_list,
	end: bool,
	sequence: i32,
	content_key: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	part: *mut wire_uint_8_list,
) {
	wire_file_upload_part_start_impl(
		port_,
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence,
		content_key,
		sign_key,
		part,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_upload_part(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	url_prefix: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	session_id: *mut wire_uint_8_list,
	end: bool,
	sequence: i32,
	content_key: *mut wire_uint_8_list,
	sign_key: *mut wire_uint_8_list,
	part: *mut wire_uint_8_list,
) {
	wire_file_upload_part_impl(
		port_,
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence,
		content_key,
		sign_key,
		part,
	)
}

#[no_mangle]
pub extern "C" fn wire_file_file_name_update(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	file_id: *mut wire_uint_8_list,
	content_key: *mut wire_uint_8_list,
	file_name: *mut wire_uint_8_list,
) {
	wire_file_file_name_update_impl(port_, base_url, auth_token, jwt, file_id, content_key, file_name)
}

#[no_mangle]
pub extern "C" fn wire_file_delete_file(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	file_id: *mut wire_uint_8_list,
	group_id: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_file_delete_file_impl(port_, base_url, auth_token, jwt, file_id, group_id, group_as_member)
}

// Section: allocate functions

#[no_mangle]
pub extern "C" fn new_box_autoadd_bool_0(value: bool) -> *mut bool {
	support::new_leak_box_ptr(value)
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_i32_0(value: i32) -> *mut i32 {
	support::new_leak_box_ptr(value)
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_u32_0(value: u32) -> *mut u32 {
	support::new_leak_box_ptr(value)
}

#[no_mangle]
pub extern "C" fn new_uint_8_list_0(len: i32) -> *mut wire_uint_8_list {
	let ans = wire_uint_8_list {
		ptr: support::new_leak_vec_ptr(Default::default(), len),
		len,
	};
	support::new_leak_box_ptr(ans)
}

// Section: related functions

// Section: impl Wire2Api

impl Wire2Api<String> for *mut wire_uint_8_list {
	fn wire2api(self) -> String {
		let vec: Vec<u8> = self.wire2api();
		String::from_utf8_lossy(&vec).into_owned()
	}
}

impl Wire2Api<bool> for *mut bool {
	fn wire2api(self) -> bool {
		unsafe { *support::box_from_leak_ptr(self) }
	}
}
impl Wire2Api<i32> for *mut i32 {
	fn wire2api(self) -> i32 {
		unsafe { *support::box_from_leak_ptr(self) }
	}
}
impl Wire2Api<u32> for *mut u32 {
	fn wire2api(self) -> u32 {
		unsafe { *support::box_from_leak_ptr(self) }
	}
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
	fn wire2api(self) -> Vec<u8> {
		unsafe {
			let wrap = support::box_from_leak_ptr(self);
			support::vec_from_leak_ptr(wrap.ptr, wrap.len)
		}
	}
}
// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
	ptr: *mut u8,
	len: i32,
}

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
	fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
	fn new_with_null_ptr() -> Self {
		std::ptr::null_mut()
	}
}

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturn(ptr: support::WireSyncReturn) {
	unsafe {
		let _ = support::box_from_leak_ptr(ptr);
	};
}
