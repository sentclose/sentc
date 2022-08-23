const chai = window.chai;

describe("User tests", () => {
	const username = "test";
	const pw = "12345";

	/** @var User */
	let user;

	before(async () => {
		const sentc = window.Sentc.default;

		await sentc.init({
			app_token: "RKXSJBwZu9Wrql3zyHxKkm3AbUqKrlpO2UU2XDBn"
		});
	});

	it("should check if username exists", async function() {
		const sentc = window.Sentc.default;

		const check = await sentc.checkUserIdentifierAvailable(username);

		chai.assert.equal(check, true);
	});

	it("should register and login a user", async function() {
		const sentc = window.Sentc.default;

		const user_id = await sentc.register(username, pw);

		user = await sentc.login(username, pw);

		chai.assert.equal(user_id, user.user_data.user_id);
	});

	it("should delete the user", async function() {
		await user.deleteUser(pw);
	});
});