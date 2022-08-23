describe("Group Test", () => {
	const username0 = "test0";
	const username1 = "test1";

	const pw = "12345";

	/** @var User */
	let user0, user1;

	/** @var Group */
	let group;

	before(async () => {
		const sentc = window.Sentc.default;

		await sentc.init({
			app_token: "RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn"
		});

		//register two users for the group

		await sentc.register(username0, pw);

		user0 = await sentc.login(username0, pw);

		await sentc.register(username1, pw);

		user1 = await sentc.login(username1, pw);
	});

	it("should create a group", async function() {
		const group_id = await user0.createGroup();

		group = await user0.getGroup(group_id);

		chai.assert.equal(group.data.group_id, group_id);
	});

	it("should not get the group when user is not in the group", async function() {
		try {
			await user1.getGroup(group.data.group_id);
		} catch (e) {
			const error = JSON.parse(e);

			chai.assert.equal(error.status, "server_310");
		}
	});

	it("should invite the 2nd user in this group", async function() {
		await group.invite(user1.user_data.user_id);
	});

	after(async () => {
		//clean up

		await group.deleteGroup();

		await user0.deleteUser(pw);
		await user1.deleteUser(pw);
	});
});