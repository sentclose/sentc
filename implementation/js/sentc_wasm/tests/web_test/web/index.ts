import {Sentc} from "../../../lib";

export async function run()
{
	//app public token: RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn
	//app sec token: YLPFfqKbFG0qgLpAMxzaavYwO5DK2mTScBK6YAXmo9QOS+MgXKHJXhPVwRq3lLZWaPg=

	const sentc = await Sentc.init({
		app_token: "RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn"
	});

	console.log("_________________________________");

	console.log("prepare fn");

	const username = "admin";
	const pw = "hello";

	console.log("prepare check username");

	const check_username_out = sentc.prepareCheckUserIdentifierAvailable(username);

	console.log(check_username_out);

	console.log("register user");
	const register_out = sentc.prepareRegister(username, pw);

	console.log(register_out);

	console.log("_________________________________");

	console.log("real usage");

	console.log("check username");

	const check = await sentc.checkUserIdentifierAvailable(username);

	if (!check) {
		throw new Error("Username found");
	}

	await sentc.register(username, pw);

	console.log("login");

	await sentc.login(username, pw);

	console.log("create and get group");

	const group_id = await sentc.createGroup();

	const group = await sentc.getGroup(group_id);

	console.log(group);

	console.log("group key rotation");

	await group.keyRotation();

	await group.finishKeyRotation();

	console.log("group delete");

	await group.deleteGroup();

	console.log("user delete");
	await sentc.deleteUser(pw);
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