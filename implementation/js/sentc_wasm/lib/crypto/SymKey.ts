/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */
import {AbstractSymCrypto} from "./AbstractSymCrypto";

export class SymKey extends AbstractSymCrypto
{
	constructor(
		base_url:string,
		app_token: string,
		private key: string,
		private key_id: string,
		public master_key_id: string	//this is important to save it to decrypt this key later
	) {
		super(base_url, app_token);
	}

	getSymKeyById(): Promise<string>
	{
		return Promise.resolve(this.key);
	}

	getSymKeyToEncrypt(): Promise<[string, string]>
	{
		return Promise.resolve([this.key, this.key_id]);
	}

	registerKey(): Promise<SymKey> {
		throw new Error("Register key is not Supported for generated key");
	}

	generateNonRegisteredKey(): Promise<[string, string, string]> {
		throw new Error("Register key is not Supported for generated key");
	}

	fetchKey(): Promise<SymKey> {
		throw new Error("Fetching the key again is not supported");
	}
}