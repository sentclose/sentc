import init, { register_test_full, register,prepare_login,done_login,simulate_server_done_login,simulate_server_prepare_login } from './pkg/sentc_wasm.js';

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
	let register_out = register(pw);

	console.log(register_out);
	console.log("real 1 json pretty");

	console.log("_________________________________");
	console.log("login")
	console.log("prepare login")
	let prep_server_out = simulate_server_prepare_login(register_out)

	let prep = prepare_login(pw,prep_server_out);
	/** @param {PrepareLoginData} */
	let prep_login_data = JSON.parse(prep);

	console.log(prep_login_data);

	let done_login_server_out = simulate_server_done_login(register_out);
	let key_data = done_login(JSON.stringify(prep_login_data.master_key_encryption_key),done_login_server_out);

	/** @param {KeyData} */
	let keys = JSON.parse(key_data);
	console.log(keys);
}
