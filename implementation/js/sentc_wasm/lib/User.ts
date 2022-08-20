import {AbstractAsymCrypto} from "./crypto/AbstractAsymCrypto";
import {GroupInviteListItem, USER_KEY_STORAGE_NAMES, UserData} from "./Enities";
import {
	change_password, decode_jwt, delete_user,
	group_accept_invite, group_create_group,
	group_get_invites_for_user,
	group_join_req, group_prepare_create_group,
	group_reject_invite, reset_password,
	update_user
} from "../pkg";
import {Sentc} from "./Sentc";
import {getGroup} from "./Group";

/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/08/20
 */

export class User extends AbstractAsymCrypto
{
	constructor(
		base_url: string,
		app_token: string,
		public user_data: UserData,
		private userIdentifier: string,
		public group_invites: GroupInviteListItem[] = []
	) {
		super(base_url, app_token);
	}

	getPrivateKey(): Promise<string>
	{
		return Promise.resolve(this.user_data.private_key);
	}

	async getPublicKey(reply_id: string): Promise<[string, string]>
	{
		const public_key = await Sentc.getUserPublicKeyData(this.base_url, this.app_token, reply_id);

		return [public_key.key, public_key.id];
	}

	getSignKey(): Promise<string>
	{
		return Promise.resolve(this.user_data.sign_key);
	}

	public async getJwt()
	{
		const jwt_data = decode_jwt(this.user_data.jwt);

		const exp = jwt_data.get_exp();

		if (exp <= Date.now() / 1000 + 30) {
			//refresh even when the jwt is valid for 30 sec
			//update the user data to safe the updated values, we don't need the class here
			this.user_data.jwt = await Sentc.refreshJwt(this.user_data.jwt, this.user_data.refresh_token);

			const storage = await Sentc.getStore();

			//save the user data with the new jwt
			await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + this.userIdentifier, this.user_data);
		}

		return this.user_data.jwt;
	}

	public updateUser(newIdentifier: string)
	{
		return update_user(
			this.base_url,
			this.app_token,
			this.user_data.jwt,
			newIdentifier
		);
	}

	public async resetPassword(newPassword: string)
	{
		//check if the user is logged in with a valid jwt and got the private keys

		const jwt = await this.getJwt();

		const decryptedPrivateKey = this.user_data.private_key;
		const decryptedSignKey = this.user_data.sign_key;

		return reset_password(
			this.base_url,
			this.app_token,
			jwt,
			newPassword,
			decryptedPrivateKey,
			decryptedSignKey
		);
	}

	public changePassword(oldPassword:string, newPassword:string)
	{
		return change_password(
			this.base_url,
			this.app_token,
			this.userIdentifier,
			oldPassword,
			newPassword
		);
	}

	public async logOut()
	{
		const storage = await Sentc.getStore();

		await storage.delete(this.userIdentifier);
	}

	public async deleteUser(password: string)
	{
		await delete_user(
			this.base_url,
			this.app_token,
			this.userIdentifier,
			password
		);

		return this.logOut();
	}

	//__________________________________________________________________________________________________________________

	public async getGroupInvites(last_fetched_item: GroupInviteListItem | null = null)
	{
		const jwt = await this.getJwt();

		const last_fetched_time = last_fetched_item?.time.toString() ?? "0";
		const last_id = last_fetched_item?.group_id ?? "none";

		const out: GroupInviteListItem[] = await group_get_invites_for_user(
			this.base_url,
			this.app_token,
			jwt,
			last_fetched_time,
			last_id
		);

		return out;
	}

	public async acceptGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return group_accept_invite(
			this.base_url,
			this.app_token,
			jwt,
			group_id
		);
	}

	public async rejectGroupInvite(group_id: string)
	{
		const jwt = await this.getJwt();

		return group_reject_invite(
			this.base_url,
			this.app_token,
			jwt,
			group_id
		);
	}

	//join req
	public async groupJoinRequest(group_id: string)
	{
		const jwt = await this.getJwt();

		return group_join_req(
			this.base_url,
			this.app_token,
			jwt,
			group_id
		);
	}

	//__________________________________________________________________________________________________________________

	public prepareGroupCreate()
	{
		//important use the public key not the exported public key here!
		return group_prepare_create_group(this.user_data.public_key);
	}

	public async createGroup()
	{
		const jwt = await this.getJwt();

		return group_create_group(this.base_url, this.app_token, jwt, this.user_data.public_key);
	}

	public getGroup(group_id: string)
	{
		return getGroup(group_id, this.base_url, this.app_token, this);
	}
}