import {Sentc} from "../../../lib";

export async function run()
{
	const sentc = await Sentc.init({
		app_token: "123"
	});

	console.log("_________________________________");

	console.log("prepare fn");

	const pw = "hello";

	console.log("prepare check username");

	const check_username_out = sentc.prepareCheckUserIdentifierAvailable("admin");

	console.log(check_username_out);

	console.log("register user");
	const register_out = sentc.prepareRegister("admin", pw);

	console.log(register_out);

	console.log("_________________________________");

	console.log("real usage");

	console.log("check username");

	const check = await sentc.checkUserIdentifierAvailable("admin");

	if (!check) {
		throw new Error("Username found");
	}

	await sentc.register("admin", pw);

	console.log("login");

	await sentc.login("admin", pw);

	console.log("create and get group");

	const group_id = await sentc.createGroup();

	const group = await sentc.getGroup(group_id);

	console.log(group);
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