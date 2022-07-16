import {
	register_test_full,
	simulate_server_done_login,
	simulate_server_prepare_login,
	prepare_create,
	simulate_server_create_group,
	get_group_data,
	encrypt_symmetric,
	decrypt_symmetric,
	encrypt_string_symmetric,
	decrypt_string_symmetric,
	generate_non_register_sym_key,
	decrypt_sym_key
} from "../../../pkg";
import {GroupData} from "../../../lib/Enities";
import {Sentc} from "../../../lib";

export async function run()
{
	const sentc = await Sentc.init({
		app_token: "123"
	});

	console.log("_________________________________");

	console.log("register test");
	const string5 = register_test_full();

	console.log(string5);

	console.log("_________________________________");
	console.log("_________________________________");
	console.log("real usage");

	const pw = "hello";

	console.log("register user");
	const register_out = sentc.prepareRegister("admin", pw);

	console.log(register_out);

	console.log("_________________________________");
	console.log("login");
	console.log("prepare login");
	const prep_server_out = simulate_server_prepare_login(register_out);
	const done_login_server_out = simulate_server_done_login(register_out);

	const keys = await sentc.loginTest( prep_server_out, done_login_server_out, "admin", pw);

	console.log(keys);

	console.log("getting user");
	const user = await sentc.getUser("admin");
	console.log(user);

	console.log("_________________________________");
	console.log("create group");

	const group_create_out = prepare_create(keys.public_key);
	console.log(group_create_out);

	console.log("get group");
	const group_server_out = simulate_server_create_group(group_create_out);

	console.log(group_server_out);

	const group_data = get_group_data(keys.private_key, group_server_out);

	console.log(group_data);

	const group_keys: GroupData = JSON.parse(group_data);

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

(async () => {
	await run();
})();