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
pub extern "C" fn wire_done_register_device_start(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_done_register_device_start_impl(port_, server_output)
}

#[no_mangle]
pub extern "C" fn wire_register_device(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	server_output: *mut wire_uint_8_list,
) {
	wire_register_device_impl(port_, base_url, auth_token, jwt, server_output)
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
pub extern "C" fn wire_group_create_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_create_group_impl(port_, base_url, auth_token, jwt, group_as_member)
}

#[no_mangle]
pub extern "C" fn wire_group_create_child_group(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	parent_id: *mut wire_uint_8_list,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_create_child_group_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		parent_id,
		admin_rank,
		group_as_member,
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
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_create_connected_group_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		connected_group_id,
		admin_rank,
		group_as_member,
	)
}

#[no_mangle]
pub extern "C" fn wire_group_extract_group_data(port_: i64, server_output: *mut wire_uint_8_list) {
	wire_group_extract_group_data_impl(port_, server_output)
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
pub extern "C" fn wire_group_invite_user(
	port_: i64,
	base_url: *mut wire_uint_8_list,
	auth_token: *mut wire_uint_8_list,
	jwt: *mut wire_uint_8_list,
	id: *mut wire_uint_8_list,
	user_id: *mut wire_uint_8_list,
	rank: *mut i32,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_invite_user_impl(
		port_,
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
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
	rank: *mut i32,
	admin_rank: i32,
	group_as_member: *mut wire_uint_8_list,
) {
	wire_group_accept_join_req_impl(
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
