import {CryptoRawOutput} from "../Enities";
import {Sentc} from "../Sentc";
import {
	decrypt_raw_symmetric, decrypt_string_symmetric, decrypt_symmetric,
	encrypt_raw_symmetric, encrypt_string_symmetric,
	encrypt_symmetric
} from "../../pkg";

/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */

export class SymKey
{
	constructor(
		private base_url:string,
		private app_token: string,
		private key: string,
		private key_id: string,
		public master_key_id: string	//this is important to save it to decrypt this key later
	) {

	}

	getSymKeyToEncrypt(): Promise<[string, string]>
	{
		return Promise.resolve([this.key, this.key_id]);
	}

	public encryptRaw(data: Uint8Array): Promise<CryptoRawOutput>;

	public encryptRaw(data: Uint8Array, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Uint8Array, sign = false): Promise<CryptoRawOutput>
	{
		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		const out = encrypt_raw_symmetric(this.key, data, sign_key);

		return {
			head: out.get_head(),
			data: out.get_data()
		};
	}

	public decryptRaw(head: string, encrypted_data: Uint8Array): Uint8Array;

	public decryptRaw(head: string, encrypted_data: Uint8Array, verify_key: string): Uint8Array;

	public decryptRaw(head: string, encrypted_data: Uint8Array, verify_key = ""): Uint8Array
	{
		return decrypt_raw_symmetric(this.key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async encrypt(data: Uint8Array): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign: true): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign = false): Promise<Uint8Array>
	{
		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_symmetric(this.key, data, sign_key);
	}

	public decrypt(data: Uint8Array): Uint8Array;

	public decrypt(data: Uint8Array, verify_key: string): Uint8Array;

	public decrypt(data: Uint8Array, verify_key = ""): Uint8Array
	{
		return decrypt_symmetric(this.key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string): Promise<string>;

	public encryptString(data: string, sign: true): Promise<string>;

	public async encryptString(data: string, sign = false): Promise<string>
	{
		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_string_symmetric(this.key, data, sign_key);
	}

	public decryptString(data: string): string;

	public decryptString(data: string, verify_key: string): string;

	public decryptString(data: string, verify_key = ""): string
	{
		return decrypt_string_symmetric(this.key, data, verify_key);
	}
}