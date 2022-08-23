async function run() {
	const sentc = window.Sentc.default;

	await sentc.init({
		app_token: "RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn"
	});

	console.log("_________________________________");

	console.log("prepare fn");

	const username = "admin";
	const username_2 = "admin1";
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

	const user = await sentc.login(username, pw);

	console.log("login user 2");

	await sentc.register(username_2, pw);

	const user_2 = await sentc.login(username_2, pw);

	console.log("create and get group");

	const group_id = await user.createGroup();

	const group = await user.getGroup(group_id);

	console.log("test encrypt with std group key");

	const encrypted_by_user_1 = await group.encryptString("hello there £ Я a a");


	let group_for_user_2;

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

		group_for_user_2 = await user_2.getGroup(group_id);

		console.log("group key rotation");

		await group.keyRotation();

		console.log("get group keys after rotation for user 1");

		console.log(group.data);

		console.log("finish the key rotation for user 2");
		await group_for_user_2.finishKeyRotation();

		console.log("get group keys after rotation for user 2");

		console.log(group_for_user_2.data);

		console.log("test decrypt with older key");

		const decrypted_user_2 = await group_for_user_2.decryptString(encrypted_by_user_1);

		console.log("encrypt result: ", decrypted_user_2);

		// eslint-disable-next-line no-empty
	} catch (e) {
		console.error(e);
	}

	console.log("member of group");
	const member = await group.getMember();
	console.log(member);

	const member_user_2 = await group_for_user_2.getMember();
	console.log(member_user_2);

	try {
		console.log("create and get child group");

		const child_group_id = await group.createChildGroup();

		//both get the child group and should test key rotation
		const child_group = await group.getChildGroup(child_group_id);

		const child_group_user_2 = await group_for_user_2.getChildGroup(child_group_id);

		console.log("key rotation in child group");
		//done key rotation is not needed for the 2nd user because he got already the keys from parent
		await child_group.keyRotation();

		console.log("test encrypt after key rotation in child group");

		const encrypted_by_user_1 = await child_group.encryptString("hello there £ Я a a");

		const decrypted_user_2 = await child_group_user_2.decryptString(encrypted_by_user_1);

		console.log("encrypt result: ", decrypted_user_2);

		console.log("member of child group");
		const member = await child_group.getMember();
		console.log(member);

		const member_user_2 = await child_group_user_2.getMember();
		console.log(member_user_2);
	} catch (e) {
		console.log(e);
	}

	console.log("group delete");

	await group.deleteGroup();

	console.log("user delete");
	await user.deleteUser(pw);
	await user_2.deleteUser(pw);
}

run().then();