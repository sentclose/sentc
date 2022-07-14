import init, {
	register_test_full,
	register_test,
	prepare_login_test,
	done_login_test,
	simulate_server_done_login,
	simulate_server_prepare_login,
	prepare_create,
	simulate_server_create_group,
	get_group_data
} from './../../pkg/sentc_wasm.js';

export async function run()
{
	await init();

	console.log("_________________________________");

	console.log("register test");
	let string5 = register_test_full();

	console.log(string5);

	console.log("_________________________________");
	console.log("_________________________________");
	console.log("real usage")

	let pw = "hello";

	console.log("register user")
	let register_out = register_test("admin",pw);

	console.log(register_out);
	console.log("real 1 json pretty");

	console.log("_________________________________");
	console.log("login")
	console.log("prepare login")
	let prep_server_out = simulate_server_prepare_login(register_out)

	let prep = prepare_login_test(pw,prep_server_out);

	let done_login_server_out = simulate_server_done_login(register_out);

	let key_data = done_login_test(prep.get_master_key_encryption_key(),done_login_server_out);

	/** @param {KeyData} */
	let keys = {
		private_key: key_data.get_private_key(),
		public_key: key_data.get_public_key(),
		sign_key: key_data.get_sign_key(),
		verify_key: key_data.get_verify_key(),
	};

	let jwt = key_data.get_jwt();

	console.log(keys);
	console.log(jwt);

	console.log("_________________________________");
	console.log("create group");

	let group_create_out = prepare_create(keys.public_key);
	console.log(group_create_out);

	console.log("get group");
	let group_server_out = simulate_server_create_group(group_create_out);

	console.log(group_server_out)

	let group_data = get_group_data(keys.private_key,group_server_out);

	console.log(group_data)
	console.log(JSON.parse(group_data))
}
