/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/12
 */
import {GroupData} from "./Enities";
import {group_invite_user, group_invite_user_session, group_prepare_keys_for_new_member} from "../pkg";
import {Sentc} from "./Sentc";


export class Group
{
	constructor(private data: GroupData, private base_url: string, private app_token: string) {}

	//__________________________________________________________________________________________________________________

	public prepareKeysForNewMember(user_id: string)
	{
		const key_count = this.data.keys.length;

		//TODo get or fetch the user public data via static fn in sentc

		const key_string = JSON.stringify(this.data.keys);

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
			user_id,
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

			p.push(group_invite_user_session(this.base_url, this.app_token, jwt, this.data.group_id, session_id, user_id, next_keys[0]));

			i++;
		}

		return Promise.allSettled(p);
	}

	//__________________________________________________________________________________________________________________
	//join req


	//__________________________________________________________________________________________________________________

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
}
