import init, { register_test_full,register_test,prepare_login_test,done_login_test,simulate_server_done_login,simulate_server_prepare_login } from './pkg/sentc_wasm.js';

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
	let keys = JSON.parse(key_data);
	console.log(keys);
}
