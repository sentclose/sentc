import init, {
	register_test_full,
	register_test,
	prepare_login_test,
	done_login_test,
	simulate_server_done_login,
	simulate_server_prepare_login,
	prepare_create_group,
	simulate_server_create_group,
	get_group_data_test,
	encrypt_symmetric,
	decrypt_symmetric,
	encrypt_string_symmetric,
	decrypt_string_symmetric,
	generate_non_register_sym_key,
	decrypt_sym_key
} from "./../../../pkg/sentc_wasm.js";

export async function run()
{
	await init();

	console.log("_________________________________");

	console.log("register test");
	const string5 = register_test_full();

	console.log(string5);

	console.log("_________________________________");
	console.log("_________________________________");
	console.log("real usage");

	const pw = "hello";

	console.log("register user");
	const register_out = register_test("admin", pw);

	console.log(register_out);
	console.log("real 1 json pretty");

	console.log("_________________________________");
	console.log("login");
	console.log("prepare login");
	const prep_server_out = simulate_server_prepare_login(register_out);

	const prep = prepare_login_test("admin", pw, prep_server_out);

	const done_login_server_out = simulate_server_done_login(register_out);

	const key_data = done_login_test(prep.get_master_key_encryption_key(), done_login_server_out);

	/** @param {UserData} */
	const keys = {
		private_key: key_data.get_private_key(),
		public_key: key_data.get_public_key(),
		sign_key: key_data.get_sign_key(),
		verify_key: key_data.get_verify_key(),
		exported_public_key: key_data.get_exported_public_key(),
		exported_verify_key: key_data.get_exported_verify_key(),
		jwt: key_data.get_jwt()
	};

	console.log(keys);

	console.log("_________________________________");
	console.log("create group");

	const group_create_out = prepare_create_group(keys.public_key);
	console.log(group_create_out);

	console.log("get group");
	const group_server_out = simulate_server_create_group(group_create_out);

	console.log(group_server_out);

	const group_data = get_group_data_test(keys.private_key, group_server_out);

	console.log(group_data);

	/** @param {GroupData} */
	const group_keys = JSON.parse(group_data);

	console.log(group_keys);

	console.log(group_keys.keys[0].group_key);

	console.log("sym encrypt test");
	const text = "abc";
	const text_view = stringToByteArray(text);

	const encrypted = encrypt_symmetric(group_keys.keys[0].group_key, text_view, keys.sign_key);

	console.log(encrypted);

	const decrypted = decrypt_symmetric(group_keys.keys[0].group_key, encrypted, keys.exported_verify_key);

	console.log(byteArrayToString(decrypted));

	console.log("sym encrypt test with string");

	const encrypted_string = encrypt_string_symmetric(group_keys.keys[0].group_key, text_view, keys.sign_key);

	console.log(encrypted_string);

	const decrypted_string = decrypt_string_symmetric(group_keys.keys[0].group_key, encrypted_string, keys.exported_verify_key);

	console.log(byteArrayToString(decrypted_string));

	console.log("_________________________________");
	console.log("key generate");

	const generated_key_out = generate_non_register_sym_key(group_keys.keys[0].group_key);
	const generated_key = generated_key_out.get_key();
	const encrypted_generated_key = generated_key_out.get_encrypted_key();

	const encrypted_string1 = encrypt_string_symmetric(generated_key, text_view, keys.sign_key);

	console.log(encrypted_string1);

	const decrypted_string1 = decrypt_string_symmetric(generated_key, encrypted_string1, keys.exported_verify_key);

	console.log(byteArrayToString(decrypted_string1));

	const decrypted_generated_key = decrypt_sym_key(group_keys.keys[0].group_key, encrypted_generated_key);

	const encrypted_string2 = encrypt_string_symmetric(decrypted_generated_key, text_view, keys.sign_key);

	console.log(encrypted_string2);

	const decrypted_string2 = decrypt_string_symmetric(decrypted_generated_key, encrypted_string2, keys.exported_verify_key);

	console.log(byteArrayToString(decrypted_string2));
}

/**
 * Uses this function to transform a random string into array
 *
 * @param {string} string
 * @returns {Uint8Array}
 */
export function stringToByteArray(string)
{
	//@ts-ignore
	return new TextEncoder("utf-8").encode(string);
}

export function byteArrayToString(b)
{
	return new TextDecoder().decode(b);
}