import {Sentc} from "../../../lib";

export async function run()
{
	//app public token: RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn
	//app sec token: YLPFfqKbFG0qgLpAMxzaavYwO5DK2mTScBK6YAXmo9QOS+MgXKHJXhPVwRq3lLZWaPg=

	await Sentc.init({
		app_token: "RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn"
	});

	console.log("_________________________________");

	console.log("prepare fn");

	const username = "admin";
	const username_2 = "admin1";
	const pw = "hello";

	console.log("prepare check username");

	const check_username_out = Sentc.prepareCheckUserIdentifierAvailable(username);

	console.log(check_username_out);

	console.log("register user");
	const register_out = Sentc.prepareRegister(username, pw);

	console.log(register_out);

	console.log("_________________________________");

	console.log("real usage");

	console.log("check username");

	const check = await Sentc.checkUserIdentifierAvailable(username);

	if (!check) {
		throw new Error("Username found");
	}

	await Sentc.register(username, pw);

	console.log("login");

	const user = await Sentc.login(username, pw);

	console.log("login user 2");

	await Sentc.register(username_2, pw);

	const user_2 = await Sentc.login(username_2, pw);

	console.log("create and get group");

	const group_id = await user.createGroup();

	const group = await user.getGroup(group_id);

	try {
		console.log("invite user");

		await group.invite(user_2.user_data.user_id);

		console.log("accept group invite");

		const invites = await user_2.getGroupInvites();

		for (let i = 0; i < invites.length; i++) {
			const invite = invites[i];

			// eslint-disable-next-line no-await-in-loop
			await user_2.acceptGroupInvite(invite.group_id);
		}

		console.log("get group for the 2nd user");

		const group_for_user_2 = await user_2.getGroup(group_id);

		console.log("group key rotation");

		await group.keyRotation();

		console.log("finish the key rotation for user 2");
		await group_for_user_2.finishKeyRotation();
		// eslint-disable-next-line no-empty
	} catch (e) {
		console.error(e);
	}

	console.log("group delete");

	await group.deleteGroup();

	console.log("user delete");
	await user.deleteUser(pw);
	await user_2.deleteUser(pw);
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