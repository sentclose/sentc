import {CryptoHead, CryptoRawOutput} from "../Enities";
import {Sentc} from "../Sentc";
import {
	decrypt_raw_symmetric, decrypt_string_symmetric, decrypt_symmetric,
	deserialize_head_from_string,
	encrypt_raw_symmetric, encrypt_string_symmetric,
	encrypt_symmetric, generate_and_register_sym_key, generate_non_register_sym_key, get_sym_key_by_id,
	split_head_and_encrypted_data, split_head_and_encrypted_string
} from "../../pkg";
import {AbstractCrypto} from "./AbstractCrypto";
import {SymKey} from "./SymKey";

/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/19
 */

export abstract class AbstractSymCrypto extends AbstractCrypto
{
	/**
	 * The latest used key (e.g. the latest group key)
	 *
	 * return the key and the key id
	 */
	abstract getSymKeyToEncrypt(): Promise<[string, string]>;

	abstract getSymKeyById(key_id: string): Promise<string>;

	public encryptRaw(data: Uint8Array): Promise<CryptoRawOutput>;

	public encryptRaw(data: Uint8Array, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Uint8Array, sign = false): Promise<CryptoRawOutput>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		const out = encrypt_raw_symmetric(key[0], data, sign_key);

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

		const key = await this.getSymKeyById(de_head.id);

		return decrypt_raw_symmetric(key, encrypted_data, head, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public async encrypt(data: Uint8Array): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign: true): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign = false): Promise<Uint8Array>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_symmetric(key[0], data, sign_key);
	}

	public decrypt(data: Uint8Array): Promise<Uint8Array>;

	public decrypt(data: Uint8Array, verify_key: string): Promise<Uint8Array>;

	public async decrypt(data: Uint8Array, verify_key = ""): Promise<Uint8Array>
	{
		const head: CryptoHead = split_head_and_encrypted_data(data);

		const key = await this.getSymKeyById(head.id);

		return decrypt_symmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	public encryptString(data: string): Promise<string>;

	public encryptString(data: string, sign: true): Promise<string>;

	public async encryptString(data: string, sign = false): Promise<string>
	{
		const key = await this.getSymKeyToEncrypt();

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_string_symmetric(key[0], data, sign_key);
	}

	public decryptString(data: string): Promise<string>;

	public decryptString(data: string, verify_key: string): Promise<string>;

	public async decryptString(data: string, verify_key = ""): Promise<string>
	{
		const head: CryptoHead = split_head_and_encrypted_string(data);

		const key = await this.getSymKeyById(head.id);

		return decrypt_string_symmetric(key, data, verify_key);
	}

	//__________________________________________________________________________________________________________________

	/**
	 * Register a new symmetric key to encrypt and decrypt.
	 *
	 * This key is encrypted by the latest group key
	 *
	 * Save the key id too of the key which was used to encrypt this key!
	 *
	 * Not needed to return the encrypted key, because the other member can fetch this key by fetchKey function
	 */
	public async registerKey()
	{
		const key_data = await this.getSymKeyToEncrypt();

		const jwt = await Sentc.getJwt();

		const key_out = await generate_and_register_sym_key(this.base_url, this.app_token, jwt, key_data[0]);

		const key_id = key_out.get_key_id();
		const key = key_out.get_key();

		//return the group key id which was used to encrypt this key
		return new SymKey(this.base_url, this.app_token, key, key_id, key_data[1]);
	}

	public async generateNonRegisteredKey()
	{
		const key_data = await this.getSymKeyToEncrypt();

		const key_out = generate_non_register_sym_key(key_data[0]);

		const encrypted_key = key_out.get_encrypted_key();
		const key = key_out.get_key();

		return [new SymKey(this.base_url, this.app_token, key, "non_register", key_data[1]), encrypted_key];
	}

	public async fetchKey(key_id: string, master_key_id: string)
	{
		const key = await this.getSymKeyById(master_key_id);

		const key_out = await get_sym_key_by_id(this.base_url, this.app_token, key_id, key[0]);

		return new SymKey(this.base_url, this.app_token, key_out, key_id, master_key_id);
	}

	//__________________________________________________________________________________________________________________
}