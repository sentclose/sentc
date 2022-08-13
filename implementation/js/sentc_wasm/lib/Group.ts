/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/12
 */
import {
	CryptoHead,
	CryptoRawOutput,
	GroupData,
	GroupJoinReqListItem,
	GroupKey,
	GroupKeyRotationOut,
	USER_KEY_STORAGE_NAMES
} from "./Enities";
import {
	decrypt_raw_symmetric,
	decrypt_string_symmetric,
	decrypt_symmetric,
	deserialize_head_from_string,
	encrypt_raw_symmetric,
	encrypt_string_symmetric, encrypt_symmetric, generate_and_register_sym_key, get_sym_key_by_id,
	group_accept_join_req,
	group_delete_group,
	group_done_key_rotation,
	group_finish_key_rotation,
	group_get_group_keys,
	group_get_join_reqs,
	group_invite_user,
	group_invite_user_session,
	group_join_user_session,
	group_key_rotation,
	group_kick_user,
	group_pre_done_key_rotation,
	group_prepare_key_rotation,
	group_prepare_keys_for_new_member,
	group_prepare_update_rank,
	group_reject_join_req,
	group_update_rank,
	leave_group,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string
} from "../pkg";
import {Sentc} from "./Sentc";


export class Group
{
	constructor(private data: GroupData, private base_url: string, private app_token: string) {}

	//__________________________________________________________________________________________________________________

	//TODO create child group

	public prepareKeysForNewMember(user_id: string)
	{
		const key_count = this.data.keys.length;

		//TODo get or fetch the user public data via static fn in sentc

		const keys = [];

		for (let i = 0; i < this.data.keys.length; i++) {
			const key = this.data.keys[i].group_key;
			keys.push(key);
		}

		const key_string = JSON.stringify(keys);

		//TODO use user public key
		return group_prepare_keys_for_new_member(user_id, key_string, key_count, this.data.rank);
	}

	public async invite(user_id: string)
	{
		//TODO get or fetch the user public data via static fn in sentc

		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeyString();

		const jwt = await Sentc.getJwt();

		const session_id = await group_invite_user(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			this.data.rank,
			user_id,	//TODO use the public key here
			key_string
		);

		if (session_id === "") {
			return;
		}

		//upload the rest of the keys via session
		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeyString(i);
			next_page = next_keys[1];

			p.push(group_invite_user_session(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				session_id,
				user_id, //TODo use the public key here
				next_keys[0]
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________
	//join req

	public async getJoinRequests(last_fetched_item: GroupJoinReqListItem | null = null)
	{
		const jwt = await Sentc.getJwt();

		const reqs: GroupJoinReqListItem[] = await group_get_join_reqs(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			this.data.rank,
			last_fetched_item.time.toString(),
			last_fetched_item.user_id
		);

		return reqs;
	}

	public async rejectJoinRequest(user_id: string)
	{
		const jwt = await Sentc.getJwt();

		return group_reject_join_req(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			this.data.rank,
			user_id
		);
	}

	public async acceptJoinRequest(user_id: string)
	{
		const jwt = await Sentc.getJwt();
		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeyString();

		//TODO get or fetch the user public data via static fn in sentc

		const session_id = await group_accept_join_req(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			this.data.rank,
			user_id,	//TODo use the public key here
			key_string
		);

		if (session_id === "") {
			return;
		}

		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeyString(i);
			next_page = next_keys[1];

			p.push(group_join_user_session(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				session_id,
				user_id, //TODo use the public key here
				next_keys[0]
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________

	public async leave()
	{
		const jwt = await Sentc.getJwt();

		return leave_group(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id
		);
	}

	//__________________________________________________________________________________________________________________
	//key rotation

	public async prepareKeyRotation()
	{
		const user = await Sentc.getActualUser(true);

		return group_prepare_key_rotation(this.data.keys[this.data.keys.length - 1].group_key, user.public_key);
	}

	public async doneKeyRotation(server_output: string)
	{
		const user = await Sentc.getActualUser(true);

		return group_done_key_rotation(user.private_key, user.public_key, this.data.keys[this.data.keys.length - 1].group_key, server_output);
	}

	public async keyRotation()
	{
		const user = await Sentc.getActualUser(true);

		return group_key_rotation(this.base_url, this.app_token, user.jwt, this.data.group_id, user.public_key, this.data.keys[this.data.keys.length - 1].group_key);
	}

	public async finishKeyRotation()
	{
		const user = await Sentc.getActualUser(true);

		let keys: GroupKeyRotationOut[] = await group_pre_done_key_rotation(this.base_url, this.app_token, user.jwt, this.data.group_id);

		let next_round = false;
		let rounds_left = 10;

		do {
			const left_keys = [];

			//should be always there because the group rotation keys are ordered by time
			for (let i = 0; i < keys.length; i++) {
				const key = keys[i];

				const pre_key_index = this.data.key_map.get(key.pre_group_key_id);
				if (!pre_key_index) {
					left_keys.push(key);
					continue;
				}

				const pre_key = this.data.keys[pre_key_index];
				if (!pre_key) {
					left_keys.push(key);
					continue;
				}

				//await must be in this loop because we need the keys
				// eslint-disable-next-line no-await-in-loop
				await group_finish_key_rotation(
					this.base_url,
					this.app_token,
					user.jwt,
					this.data.group_id,
					key.server_output,
					pre_key.group_key,
					user.public_key,
					user.private_key
				);
			}

			//when it runs 10 times and there are still left -> break up
			rounds_left--;

			//fetch the new keys, when there are still keys left, maybe they are there after the key fetch -> must be in loop too
			// eslint-disable-next-line no-await-in-loop
			await this.fetchKeys(user.jwt, user.private_key);

			if (left_keys.length > 0) {
				keys = [];
				//push the not found keys into the key array, maybe the pre group keys are in the next round
				keys.push(...left_keys);

				next_round = true;
			} else {
				next_round = false;
			}
		} while (next_round && rounds_left > 0);

		//after a key rotation -> save the new group data in the store
		const storage = await Sentc.getStore();
		const group_key = USER_KEY_STORAGE_NAMES.groupData + "_id_" + this.data.group_id;
		return storage.set(group_key, this.data);
	}

	//__________________________________________________________________________________________________________________

	public prepareUpdateRank(user_id: string, new_rank: number)
	{
		return group_prepare_update_rank(user_id, new_rank, this.data.rank);
	}

	public async updateRank(user_id: string, new_rank: number)
	{
		const user = await Sentc.getActualUser(true);

		//check if the updated user is the actual user -> then update the group store

		await group_update_rank(this.base_url, this.app_token, user.jwt, this.data.group_id, user_id, new_rank, this.data.rank);
		
		if (user.user_id === user_id) {
			const storage = await Sentc.getStore();
			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_id_" + this.data.group_id;

			this.data.rank = new_rank;

			return storage.set(group_key, this.data);
		}
	}

	public async kickUser(user_id: string)
	{
		const jwt = await Sentc.getJwt();

		return group_kick_user(this.base_url, this.app_token, jwt, this.data.group_id, user_id, this.data.rank);
	}

	//__________________________________________________________________________________________________________________

	public async deleteGroup()
	{
		const jwt = await Sentc.getJwt();

		return group_delete_group(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank);
	}

	//__________________________________________________________________________________________________________________

	public async fetchKeys(jwt: string, private_key: string)
	{
		let last_item = this.data.keys[this.data.keys.length - 1];

		let next_fetch = true;

		const keys: GroupKey[] = [];

		while (next_fetch) {
			// eslint-disable-next-line no-await-in-loop
			const fetchedKeys: GroupKey[] = await group_get_group_keys(
				this.base_url,
				this.app_token,
				jwt,
				private_key,
				this.data.group_id,
				last_item.time.toString(),
				last_item.group_key_id
			);

			keys.push(...fetchedKeys);

			next_fetch = fetchedKeys.length >= 50;

			last_item = fetchedKeys[fetchedKeys.length - 1];
		}

		const last_inserted_key_index = this.data.keys.length;

		//insert in the key map
		for (let i = 0; i < keys.length; i++) {
			this.data.key_map.set(keys[i].group_key_id, i + last_inserted_key_index);
		}

		this.data.keys.push(...keys);

		//return the updated data, so it can be saved in the store
		return this.data;
	}

	private prepareKeyString(page = 0): [string, boolean]
	{
		const offset = page * 50;
		const end = (offset + 50 > this.data.keys.length - 1) ? this.data.keys.length - 1 : offset + 50;

		const key_slice = this.data.keys.slice(offset, end);

		const keys = [];

		for (let i = 0; i < key_slice.length; i++) {
			const key = this.data.keys[i].group_key;

			keys.push(key);
		}

		return [JSON.stringify(keys), end < this.data.keys.length - 1];
	}

	private async getGroupKey(key_id: string)
	{
		let key_index = this.data.key_map.get(key_id);

		if (!key_index) {
			const user = await Sentc.getActualUser(true);

			this.data = await this.fetchKeys(user.jwt, user.private_key);

			const storage = await Sentc.getStore();
			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_id_" + this.data.group_id;

			await storage.set(group_key, this.data);

			key_index = this.data.key_map.get(key_id);
			if (!key_index) {
				//key not found TODO error
				throw new Error();
			}
		}

		const key = this.data.keys[key_index]?.group_key;
		if (!key) {
			//key not found TODO error
			throw new Error();
		}

		return key;
	}

	//__________________________________________________________________________________________________________________

	public encryptRaw(data: Uint8Array): Promise<CryptoRawOutput>;

	public encryptRaw(data: Uint8Array, sign: true): Promise<CryptoRawOutput>;

	public async encryptRaw(data: Uint8Array, sign = false): Promise<CryptoRawOutput>
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		const out = encrypt_raw_symmetric(latest_key.group_key, data, sign_key);

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

		const key = await this.getGroupKey(de_head.id);

		return decrypt_raw_symmetric(key, encrypted_data, head, verify_key);
	}

	public async encrypt(data: Uint8Array): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign: true): Promise<Uint8Array>

	public async encrypt(data: Uint8Array, sign = false): Promise<Uint8Array>
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_symmetric(latest_key.group_key, data, sign_key);
	}

	public decrypt(data: Uint8Array): Promise<Uint8Array>;

	public decrypt(data: Uint8Array, verify_key: string): Promise<Uint8Array>;

	public async decrypt(data: Uint8Array, verify_key = ""): Promise<Uint8Array>
	{
		const head: CryptoHead = split_head_and_encrypted_data(data);

		const key = await this.getGroupKey(head.id);

		return decrypt_symmetric(key, data, verify_key);
	}

	public encryptString(data: string): Promise<string>;

	public encryptString(data: string, sign: true): Promise<string>;

	public async encryptString(data: string, sign = false): Promise<string>
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_string_symmetric(latest_key.group_key, data, sign_key);
	}

	public decryptString(data: string): Promise<string>;

	public decryptString(data: string, verify_key: string): Promise<string>;

	public async decryptString(data: string, verify_key = ""): Promise<string>
	{
		const head: CryptoHead = split_head_and_encrypted_string(data);

		const key = await this.getGroupKey(head.id);

		return decrypt_string_symmetric(key, data, verify_key);
	}

	/**
	 * Register a new symmetric key to encrypt and decrypt.
	 *
	 * This key is encrypted by the latest group key
	 *
	 * Save the key id too of the key which was used to encrypt this key!
	 */
	public async registerKey()
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		const jwt = await Sentc.getJwt();

		const key_id = await generate_and_register_sym_key(this.base_url, this.app_token, jwt, latest_key.group_key);

		const key = await get_sym_key_by_id(this.base_url, this.app_token, key_id, latest_key.group_key);

		//return the group key id which was used to encrypt this key
		return [key, latest_key.group_key_id];
	}

	public async fetchKey(key_id: string, group_key_id: string)
	{
		const group_key = await this.getGroupKey(group_key_id);

		return get_sym_key_by_id(this.base_url, this.app_token, key_id, group_key);
	}

	public encryptByGeneratedKey(data: Uint8Array, generated_key: string): Promise<Uint8Array>;

	public encryptByGeneratedKey(data: Uint8Array, generated_key: string, sign: true): Promise<Uint8Array>;

	public async encryptByGeneratedKey(data: Uint8Array, generated_key: string, sign = false)
	{
		let sign_key = "";

		if (sign) {
			const user = await Sentc.getActualUser();

			sign_key = user.sign_key;
		}

		return encrypt_symmetric(generated_key, data, sign_key);
	}

	public decryptByGeneratedKey(data: Uint8Array, generated_key: string): Promise<Uint8Array>;

	public decryptByGeneratedKey(data: Uint8Array, generated_key: string, verify_key: string): Promise<Uint8Array>;

	public decryptByGeneratedKey(data: Uint8Array, generated_key: string, verify_key = ""): Promise<Uint8Array>
	{
		return Promise.resolve(decrypt_symmetric(generated_key, data, verify_key));
	}
}
