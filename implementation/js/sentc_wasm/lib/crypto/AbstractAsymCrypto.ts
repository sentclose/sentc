/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */
import {AbstractCrypto} from "./AbstractCrypto";
import {CryptoHead, CryptoRawOutput} from "../Enities";
import {
	decrypt_asymmetric,
	decrypt_raw_asymmetric,
	decrypt_string_asymmetric,
	deserialize_head_from_string,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_string_asymmetric,
	generate_and_register_sym_key_by_public_key,
	generate_non_register_sym_key_by_public_key,
	get_sym_key_by_id_by_private_key,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string
} from "../../pkg";
import {SymKey} from "./SymKey";

export abstract class AbstractAsymCrypto extends AbstractCrypto
{
	/**
	 * Fetch the public key for this user
	 *
	 * @param reply_id
	 */
	abstract getPublicKey(reply_id: string): Promise<[string, string]>;

	/**
	 * Get the own private key
	 * because only the actual user got access to the private key
	 *
	 * @param key_id
	 */
	abstract getPrivateKey(key_id: string): Promise<string>;

	abstract getSignKey(): Promise<string>;

	abstract getJwt(): Promise<string>;

	public encryptRaw(data: Uint8Array, reply_id: string): Promise<CryptoRawOutput>;

	public encryptRaw(data: Uint8Array, reply_id: string, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Uint8Array, reply_id: string, sign = false): Promise<CryptoRawOutput>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key = "";

		if (sign) {
			sign_key = await this.getSignKey();
		}

		const out = encrypt_raw_asymmetric(key[0], data, sign_key);

		return {
			head: out.get_head(),
			data: out.get_data()
		};
	}

	public decryptRaw(head: string, encrypted_data: Uint8Array): Promise<Uint8Array>;

	public decryptRaw(head: string, encrypted_data: Uint8Array, verify_key: string): Promise<Uint8Array>;

	public async decryptRaw(head: string, encrypted_data: Uint8Array, verify_key = ""): Promise<Uint8Array>
	{
		const de_head: CryptoHead = deserialize_head_from_string(head);

		const key = await this.getPrivateKey(de_head.id);

		return decrypt_raw_asymmetric(key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async encrypt(data: Uint8Array, reply_id: string): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, reply_id: string, sign: true): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, reply_id: string, sign = false): Promise<Uint8Array>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key = "";

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encrypt_asymmetric(key[0], data, sign_key);
	}

	public decrypt(data: Uint8Array): Promise<Uint8Array>;

	public decrypt(data: Uint8Array, verify_key: string): Promise<Uint8Array>;

	public async decrypt(data: Uint8Array, verify_key = ""): Promise<Uint8Array>
	{
		const head: CryptoHead = split_head_and_encrypted_data(data);
		const key = await this.getPrivateKey(head.id);

		return decrypt_asymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string, reply_id:string): Promise<string>;

	public encryptString(data: string, reply_id:string, sign: true): Promise<string>;

	public async encryptString(data: string, reply_id:string, sign = false): Promise<string>
	{
		const key = await this.getPublicKey(reply_id);

		let sign_key = "";

		if (sign) {
			sign_key = await this.getSignKey();
		}

		return encrypt_string_asymmetric(key[0], data, sign_key);
	}

	public decryptString(data: string): Promise<string>;

	public decryptString(data: string, verify_key: string): Promise<string>;

	public async decryptString(data: string, verify_key = ""): Promise<string>
	{
		const head: CryptoHead = split_head_and_encrypted_string(data);
		const key = await this.getPrivateKey(head.id);

		return decrypt_string_asymmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async registerKey(reply_id:string)
	{
		const key_data = await this.getPublicKey(reply_id);

		const jwt = await this.getJwt();

		const key_out = await generate_and_register_sym_key_by_public_key(this.base_url, this.app_token, jwt, key_data[0]);

		const key_id = key_out.get_key_id();
		const key = key_out.get_key();

		return new SymKey(this.base_url, this.app_token, key, key_id, key_data[1], await this.getSignKey());
	}

	public async generateNonRegisteredKey(reply_id:string)
	{
		const key_data = await this.getPublicKey(reply_id);

		const key_out = generate_non_register_sym_key_by_public_key(key_data[0]);

		const encrypted_key = key_out.get_encrypted_key();
		const key = key_out.get_key();

		return [new SymKey(this.base_url, this.app_token, key, "non_register", key_data[1], await this.getSignKey()), encrypted_key];
	}

	public async fetchGeneratedKey(key_id: string, master_key_id: string)
	{
		const private_key = await this.getPrivateKey(master_key_id);

		const key_out = await get_sym_key_by_id_by_private_key(this.base_url, this.app_token, key_id, private_key);

		return new SymKey(this.base_url, this.app_token, key_out, key_id, master_key_id, await this.getSignKey());
	}
}