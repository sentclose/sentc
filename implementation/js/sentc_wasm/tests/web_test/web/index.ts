import {Sentc} from "../../../lib";

export async function run()
{
	const sentc = await Sentc.init({
		app_token: "123"
	});

	console.log("_________________________________");
	console.log("_________________________________");
	console.log("real usage");

	const pw = "hello";

	console.log("register user");
	const register_out = sentc.prepareRegister("admin", pw);

	console.log(register_out);

	console.log("_________________________________");
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