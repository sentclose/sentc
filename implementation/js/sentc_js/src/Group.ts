/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/12
 */
import {
	GroupData,
	GroupJoinReqListItem,
	GroupKey,
	GroupKeyRotationOut,
	GroupOutDataKeys, GroupUserListItem,
	KeyRotationInput,
	USER_KEY_STORAGE_NAMES
} from "./Enities";
import {
	group_accept_join_req,
	group_create_child_group,
	group_decrypt_key,
	group_delete_group,
	group_done_key_rotation,
	group_finish_key_rotation,
	group_get_done_key_rotation_server_input,
	group_get_group_data,
	group_get_group_key,
	group_get_group_keys,
	group_get_group_updates,
	group_get_join_reqs,
	group_get_member,
	group_invite_user,
	group_invite_user_session,
	group_join_user_session,
	group_key_rotation,
	group_kick_user,
	group_pre_done_key_rotation,
	group_prepare_create_group,
	group_prepare_key_rotation,
	group_prepare_keys_for_new_member,
	group_prepare_update_rank,
	group_reject_join_req,
	group_update_rank,
	leave_group
} from "sentc_wasm";
import {Sentc} from "./Sentc";
import {AbstractSymCrypto} from "./crypto/AbstractSymCrypto";
import {User} from "./User";

/**
 * Get a group, from the storage or the server
 *
 */
export async function getGroup(group_id: string, base_url: string, app_token: string, user: User, parent = false)
{
	const storage = await Sentc.getStore();

	const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + user.user_data.user_id + "_id_" + group_id;

	const group: GroupData = await storage.getItem(group_key);

	const jwt = await user.getJwt();

	if (group) {
		const update = await group_get_group_updates(base_url, app_token, jwt, group_id);

		group.rank = update.get_rank();
		group.key_update = update.get_key_update();

		return new Group(group, base_url, app_token, user);
	}

	const out = await group_get_group_data(
		base_url,
		app_token,
		jwt,
		group_id
	);

	//save the fetched keys but only decrypt them when creating the group obj
	const fetched_keys: GroupOutDataKeys[] = out.get_keys();

	let group_data: GroupData = {
		group_id: out.get_group_id(),
		parent_group_id: out.get_parent_group_id(),
		from_parent: parent,
		rank: out.get_rank(),
		key_update: out.get_key_update(),
		create_time: out.get_created_time(),
		joined_time: out.get_joined_time(),
		keys: [],
		key_map: new Map()
	};

	const group_obj = new Group(group_data, base_url, app_token, user);

	//update the group obj and the group data (which we saved in store) with the decrypted keys.
	//it is ok to use the private key with an empty array,
	// because we are using the keys of the parent group when this is a child group
	const keys = await group_obj.decryptKey(fetched_keys);
	group_data.keys = keys;
	group_obj.groupKeys = keys;

	const key_map: Map<string, number> = new Map();

	//insert in the key map
	for (let i = 0; i < keys.length; i++) {
		key_map.set(keys[i].group_key_id, i);
	}
	group_data.key_map = key_map;
	group_obj.groupKeyMap = key_map;

	if (keys.length >= 50) {
		//fetch the rest of the keys via pagination, get the updated data back
		group_data = await group_obj.fetchKeys(jwt);
	}

	//store the group data
	await storage.set(group_key, group_data);

	return group_obj;
}

export class Group extends AbstractSymCrypto
{
	constructor(public data: GroupData, base_url: string, app_token: string, private user: User) {
		super(base_url, app_token);
	}

	set groupKeys(keys: GroupKey[])
	{
		this.data.keys = keys;
	}

	set groupKeyMap(key_map: Map<string, number>)
	{
		this.data.key_map = key_map;
	}

	//__________________________________________________________________________________________________________________

	public getChildGroup(group_id: string)
	{
		return getGroup(group_id, this.base_url, this.app_token, this.user, true);
	}

	public prepareCreateChildGroup()
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		const group_input = group_prepare_create_group(latest_key.public_group_key);

		return [group_input, latest_key.group_key_id];
	}

	public async createChildGroup()
	{
		const latest_key = this.data.keys[this.data.keys.length - 1].public_group_key;

		const jwt = await this.user.getJwt();

		return group_create_child_group(this.base_url, this.app_token, jwt, latest_key, this.data.group_id, this.data.rank);
	}

	public async getMember(last_fetched_item: GroupUserListItem | null = null)
	{
		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.joined_time.toString() ?? "0";
		const last_id = last_fetched_item?.user_id ?? "none";

		const list: GroupUserListItem[] = await group_get_member(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			last_fetched_time,
			last_id
		);

		return list;
	}

	public async prepareKeysForNewMember(user_id: string)
	{
		const key_count = this.data.keys.length;
		
		const public_key = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);

		const keys = [];

		for (let i = 0; i < this.data.keys.length; i++) {
			const key = this.data.keys[i].group_key;
			keys.push(key);
		}

		const key_string = JSON.stringify(keys);

		return group_prepare_keys_for_new_member(public_key.key, key_string, key_count, this.data.rank);
	}

	public invite(user_id: string)
	{
		return this.inviteUserInternally(user_id);
	}

	public inviteAuto(user_id: string)
	{
		return this.inviteUserInternally(user_id, true);
	}

	private async inviteUserInternally(user_id: string, auto = false)
	{
		const public_key = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);

		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeys();

		const jwt = await this.user.getJwt();

		const session_id = await group_invite_user(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			this.data.rank,
			auto,
			public_key.key,
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
			const next_keys = this.prepareKeys(i);
			next_page = next_keys[1];

			p.push(group_invite_user_session(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				session_id,
				public_key.key,
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
		const jwt = await this.user.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.user_id ?? "none";

		const reqs: GroupJoinReqListItem[] = await group_get_join_reqs(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			this.data.rank,
			last_fetched_time,
			last_id
		);

		return reqs;
	}

	public async rejectJoinRequest(user_id: string)
	{
		const jwt = await this.user.getJwt();

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
		const jwt = await this.user.getJwt();
		const key_count = this.data.keys.length;
		const [key_string] = this.prepareKeys();

		const public_key = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, user_id);

		const session_id = await group_accept_join_req(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id,
			user_id,
			key_count,
			this.data.rank,
			public_key.key,
			key_string
		);

		if (session_id === "") {
			return;
		}

		let next_page = true;
		let i = 1;
		const p = [];

		while (next_page) {
			const next_keys = this.prepareKeys(i);
			next_page = next_keys[1];

			p.push(group_join_user_session(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				session_id,
				public_key.key,
				next_keys[0]
			));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________

	public async leave()
	{
		const jwt = await this.user.getJwt();

		return leave_group(
			this.base_url,
			this.app_token,
			jwt,
			this.data.group_id
		);
	}

	//__________________________________________________________________________________________________________________
	//key rotation

	/**
	 * Get the actual used public key.
	 * For the user, or if user joined via parent group the parent group public key
	 *
	 * Returns only the public key format, not the exported public key!
	 *
	 * @private
	 */
	private async getPublicKey()
	{
		let public_key;

		if (!this.data.from_parent) {
			public_key = this.user.user_data.public_key;
		} else {
			//get parent group public key
			const storage = await Sentc.getStore();
			const parent_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.parent_group_id;
			const parent_group: GroupData = await storage.getItem(parent_group_key);

			if (!parent_group) {
				//TODO err handling
				throw new Error();
			}

			//use the latest key
			public_key = parent_group.keys[parent_group.keys.length - 1].public_group_key;
		}

		return public_key;
	}

	/**
	 * Gets the right private key to the used public key
	 *
	 * If it is from user -> get it from user
	 *
	 * If not then form the parent group
	 *
	 * @param private_key_id
	 * @private
	 */
	private async getPrivateKey(private_key_id: string)
	{
		if (!this.data.from_parent) {
			return this.user.getPrivateKey();
		}

		//get parent group private key
		const storage = await Sentc.getStore();
		const parent_group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.parent_group_id;
		const parent_group_data: GroupData = await storage.getItem(parent_group_key);

		if (!parent_group_data) {
			//TODO err handling
			throw new Error();
		}

		const parent_group = new Group(parent_group_data, this.base_url, this.app_token, this.user);

		//private key id got the same id as the group key
		const group_key = await parent_group.getGroupKey(private_key_id);

		//use the latest key
		return group_key.private_group_key;
	}

	private getKeyRotationServerOut(server_output: string): KeyRotationInput
	{
		const de_server_output = group_get_done_key_rotation_server_input(server_output);

		return {
			encrypted_eph_key_key_id: de_server_output.get_encrypted_eph_key_key_id(),
			encrypted_ephemeral_key_by_group_key_and_public_key: de_server_output.get_encrypted_ephemeral_key_by_group_key_and_public_key(),
			encrypted_group_key_by_ephemeral: de_server_output.get_encrypted_group_key_by_ephemeral(),
			ephemeral_alg: de_server_output.get_ephemeral_alg(),
			new_group_key_id: de_server_output.get_new_group_key_id(),
			previous_group_key_id: de_server_output.get_previous_group_key_id(),
			time: de_server_output.get_time()
		};
	}

	/**
	 * Prepares the key rotation to use it with own backend.
	 *
	 * The newest public key is used to encrypt the key for the starter.
	 * If the starter joined via parent group then the parent group public key is used
	 */
	public async prepareKeyRotation()
	{
		//if this is a child group -> start the key rotation with the parent key!
		const public_key = await this.getPublicKey();

		return group_prepare_key_rotation(this.data.keys[this.data.keys.length - 1].group_key, public_key);
	}

	public async doneKeyRotation(server_output: string)
	{
		const out = this.getKeyRotationServerOut(server_output);

		const [public_key, private_key] = await Promise.all([
			this.getPublicKey(),
			this.getPrivateKey(out.encrypted_eph_key_key_id)
		]);

		return group_done_key_rotation(private_key, public_key, this.data.keys[this.data.keys.length - 1].group_key, server_output);
	}

	public async keyRotation()
	{
		const jwt = await this.user.getJwt();

		const public_key = await this.getPublicKey();

		const key_id = await group_key_rotation(this.base_url, this.app_token, jwt, this.data.group_id, public_key, this.data.keys[this.data.keys.length - 1].group_key);

		return this.getGroupKey(key_id);
	}

	public async finishKeyRotation()
	{
		const jwt = await this.user.getJwt();

		let keys: GroupKeyRotationOut[] = await group_pre_done_key_rotation(this.base_url, this.app_token, jwt, this.data.group_id);

		let next_round = false;
		let rounds_left = 10;

		//use always the newest public key
		const public_key = await this.getPublicKey();

		do {
			const left_keys = [];

			//should be always there because the group rotation keys are ordered by time
			for (let i = 0; i < keys.length; i++) {
				const key = keys[i];

				let pre_key;

				try {
					// eslint-disable-next-line no-await-in-loop
					pre_key = await this.getGroupKey(key.pre_group_key_id);
					// eslint-disable-next-line no-empty
				} catch (e) {
					//key not found -> try the next round
				}

				if (pre_key === undefined) {
					left_keys.push(key);
					continue;
				}

				//get the right used private key for each key
				// eslint-disable-next-line no-await-in-loop
				const private_key = await this.getPrivateKey(key.encrypted_eph_key_key_id);

				//await must be in this loop because we need the keys
				// eslint-disable-next-line no-await-in-loop
				await group_finish_key_rotation(
					this.base_url,
					this.app_token,
					jwt,
					this.data.group_id,
					key.server_output,
					pre_key.group_key,
					public_key,
					private_key
				);
				
				//now get the new key and safe it
				// eslint-disable-next-line no-await-in-loop
				await this.getGroupKey(key.new_group_key_id);
			}

			//when it runs 10 times and there are still left -> break up
			rounds_left--;

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
		const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.group_id;
		return storage.set(group_key, this.data);
	}

	//__________________________________________________________________________________________________________________

	public prepareUpdateRank(user_id: string, new_rank: number)
	{
		return group_prepare_update_rank(user_id, new_rank, this.data.rank);
	}

	public async updateRank(user_id: string, new_rank: number)
	{
		const jwt = await this.user.getJwt();

		//check if the updated user is the actual user -> then update the group store

		await group_update_rank(this.base_url, this.app_token, jwt, this.data.group_id, user_id, new_rank, this.data.rank);
		
		if (this.user.user_data.user_id === user_id) {
			const storage = await Sentc.getStore();
			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.group_id;

			this.data.rank = new_rank;

			return storage.set(group_key, this.data);
		}
	}

	public async kickUser(user_id: string)
	{
		const jwt = await this.user.getJwt();

		return group_kick_user(this.base_url, this.app_token, jwt, this.data.group_id, user_id, this.data.rank);
	}

	//__________________________________________________________________________________________________________________

	public async deleteGroup()
	{
		const jwt = await this.user.getJwt();

		return group_delete_group(this.base_url, this.app_token, jwt, this.data.group_id, this.data.rank);
	}

	//__________________________________________________________________________________________________________________

	public async fetchKeys(jwt: string)
	{
		let last_item = this.data.keys[this.data.keys.length - 1];

		let next_fetch = true;

		const keys: GroupKey[] = [];

		while (next_fetch) {
			// eslint-disable-next-line no-await-in-loop
			const fetchedKeys: GroupOutDataKeys[] = await group_get_group_keys(
				this.base_url,
				this.app_token,
				jwt,
				this.data.group_id,
				last_item.time,
				last_item.group_key_id
			);

			// eslint-disable-next-line no-await-in-loop
			const decrypted_key = await this.decryptKey(fetchedKeys);

			keys.push(...decrypted_key);

			next_fetch = fetchedKeys.length >= 50;

			last_item = decrypted_key[fetchedKeys.length - 1];
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

	/**
	 * Decrypt the key with the right private key.
	 *
	 * get the right private key for each key
	 *
	 * @param fetchedKeys
	 */
	public async decryptKey(fetchedKeys: GroupOutDataKeys[]): Promise<GroupKey[]>
	{
		const keys: GroupKey[] = [];

		for (let i = 0; i < fetchedKeys.length; i++) {
			const fetched_key = fetchedKeys[i];

			// eslint-disable-next-line no-await-in-loop
			const private_key = await this.getPrivateKey(fetched_key.private_key_id);

			const decrypted_keys = group_decrypt_key(private_key, fetched_key.key_data);

			keys.push({
				group_key_id: decrypted_keys.get_group_key_id(),
				group_key: decrypted_keys.get_group_key(),
				private_group_key: decrypted_keys.get_private_group_key(),
				time: decrypted_keys.get_time(),
				public_group_key: decrypted_keys.get_public_group_key()
			});
		}

		return keys;
	}

	private prepareKeys(page = 0): [string, boolean]
	{
		const offset = page * 50;
		const end = offset + 50;

		const key_slice = this.data.keys.slice(offset, end);

		let str = "[";

		for (let i = 0; i < key_slice.length; i++) {
			const key = this.data.keys[i].group_key;

			str += key + ",";
		}

		//remove the trailing comma
		str = str.slice(0, -1);

		str += "]";

		//it must be this string: [{"Aes":{"key":"D29y+nli2g4wn1GawdVmeGyo+W8HKc1cllkzqdEA2bA=","key_id":"123"}}]

		return [str, end < this.data.keys.length - 1];
	}

	private async getGroupKey(key_id: string)
	{
		let key_index = this.data.key_map.get(key_id);

		if (key_index === undefined) {
			const jwt = await this.user.getJwt();

			const fetched_key = await group_get_group_key(this.base_url, this.app_token, jwt, this.data.group_id, key_id);

			const key: GroupOutDataKeys = {
				key_data: fetched_key.get_key_data(),
				private_key_id: fetched_key.get_private_key_id()
			};

			const decrypted_key = await this.decryptKey([key]);

			const last_inserted_key_index = this.data.keys.length;
			this.data.keys.push(decrypted_key[0]);
			this.data.key_map.set(decrypted_key[0].group_key_id, last_inserted_key_index);

			const storage = await Sentc.getStore();
			const group_key = USER_KEY_STORAGE_NAMES.groupData + "_user_" + this.user.user_data.user_id + "_id_" + this.data.group_id;

			await storage.set(group_key, this.data);

			key_index = this.data.key_map.get(key_id);
			if (!key_index) {
				//key not found TODO error
				throw new Error();
			}
		}

		const key = this.data.keys[key_index];
		if (!key) {
			//key not found TODO error
			throw new Error();
		}

		return key;
	}

	//__________________________________________________________________________________________________________________

	getSymKeyToEncrypt(): Promise<[string, string]>
	{
		const latest_key = this.data.keys[this.data.keys.length - 1];

		return Promise.resolve([latest_key.group_key, latest_key.group_key_id]);
	}

	async getSymKeyById(key_id: string): Promise<string>
	{
		const key = await this.getGroupKey(key_id);

		return key.group_key;
	}

	getJwt(): Promise<string>
	{
		return this.user.getJwt();
	}

	getSignKey(): Promise<string>
	{
		//always use the users sign key
		return this.user.getSignKey();
	}
}
