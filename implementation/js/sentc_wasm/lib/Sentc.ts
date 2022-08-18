/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/07/16
 */

import init, {
	register,
	check_user_identifier_available,
	prepare_register,
	login,
	prepare_check_user_identifier_available,
	done_check_user_identifier_available,
	done_register,
	decode_jwt,
	reset_password,
	update_user,
	change_password,
	delete_user,
	group_get_invites_for_user,
	group_accept_invite,
	group_reject_invite,
	group_join_req,
	user_fetch_public_key,
	user_fetch_public_data,
	user_fetch_verify_key,
	group_prepare_create_group,
	group_create_group,
	prepare_login_start,
	prepare_login,
	done_login, refresh_jwt, init_user
} from "../pkg";
import {GroupInviteListItem, USER_KEY_STORAGE_NAMES, UserData, UserId} from "./Enities";
import {ResCallBack, StorageFactory, StorageInterface} from "./core";
import {getGroup} from "./Group";

export const enum REFRESH_ENDPOINT {
	cookie,
	cookie_fn,
	api
}

export interface RefreshOptions {
	endpoint_url?: string,
	endpoint_fn?: (old_jwt: string) => Promise<string>,
	endpoint: REFRESH_ENDPOINT
}

export interface StorageOptions {
	errCallBack: ResCallBack,
}

export interface SentcOptions {
	base_url?: string,
	app_token: string,
	refresh?: RefreshOptions,
	storage?: StorageOptions
}

export class Sentc
{
	private static sentc: Sentc = null;

	private static init_storage = false;

	private static storage: StorageInterface;

	//@ts-ignore
	private static options: SentcOptions = {};

	//the first page of the group invites for the user
	// eslint-disable-next-line @typescript-eslint/no-empty-function
	private constructor(public group_invites: GroupInviteListItem[] = []) {}
	
	public static async getStore()
	{
		//only init when needed
		if (this.init_storage) {
			//dont init again
			return this.storage;
		}

		this.storage = await StorageFactory.getStorage(this.options.storage.errCallBack, "sentclose", "keys");

		this.init_storage = true;

		return this.storage;
	}

	public static async init(options: SentcOptions)
	{
		if (this.sentc) {
			return this.sentc;
		}

		await init();	//init wasm

		const base_url = options?.base_url ?? "http://127.0.0.1:3002";	//TODO change base url

		let errCallBack: ResCallBack;

		if (options?.storage?.errCallBack) {
			errCallBack = options?.storage?.errCallBack;
		} else {
			errCallBack = ({err, warn}) => {
				console.error(err);
				console.warn(warn);
			};
		}

		const refresh: RefreshOptions = options?.refresh ?? {
			endpoint: REFRESH_ENDPOINT.api,
			endpoint_url: base_url + "/api/v1/refresh"
		};

		Sentc.options = {
			base_url,
			app_token: options?.app_token,
			storage: {errCallBack},
			refresh
		};

		//save the invites if we fetched them from init request
		let invites: GroupInviteListItem[] = [];

		try {
			const [user, username] = await this.getActualUser(false, true);

			let jwt;

			if (refresh?.endpoint === REFRESH_ENDPOINT.api) {
				//if refresh over api -> then do the init
				const out = await init_user(options.base_url, options.app_token, user.jwt, user.refresh_token);
				invites = out.get_invites();

				jwt = out.get_jwt();
			} else {
				//if refresh over cookie -> do normal refresh jwt
				jwt = await this.refreshJwt(user.jwt, user.refresh_token);
			}

			const storage = await this.getStore();

			user.jwt = jwt;
			//save the user data with the new jwt
			await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + username, user);
		} catch (e) {
			//user was not logged in -> do nothing
		}

		this.sentc = new Sentc(invites);

		return this.sentc;
	}

	public checkUserIdentifierAvailable(userIdentifier: string)
	{
		if (userIdentifier === "") {
			return false;
		}

		return check_user_identifier_available(Sentc.options.base_url, Sentc.options.app_token, userIdentifier);
	}

	public prepareCheckUserIdentifierAvailable(userIdentifier: string)
	{
		if (userIdentifier === "") {
			return false;
		}

		return prepare_check_user_identifier_available(userIdentifier);
	}

	public doneCheckUserIdentifierAvailable(serverOutput: string)
	{
		return done_check_user_identifier_available(serverOutput);
	}

	/**
	 * Generates the register input for the api.
	 *
	 * It can be used in an external backend
	 *
	 * @param userIdentifier
	 * @param password
	 */
	public prepareRegister(userIdentifier: string, password: string)
	{
		return prepare_register(userIdentifier, password);
	}

	/**
	 * Validates the register output from the api when using prepare register function
	 *
	 * @param serverOutput
	 */
	public doneRegister(serverOutput: string)
	{
		return done_register(serverOutput);
	}

	/**
	 * Register a new user.
	 *
	 * @param userIdentifier
	 * @param password
	 * @throws Error
	 * - if username exists
	 * - request error
	 */
	public register(userIdentifier: string, password: string): Promise<UserId> | false
	{
		if (userIdentifier === "" || password === "") {
			return false;
		}

		return register(Sentc.options.base_url, Sentc.options.app_token, userIdentifier, password);
	}

	/**
	 * Make the first login request to get the salt
	 */
	public prepareLoginStart(userIdentifier: string)
	{
		return prepare_login_start(Sentc.options.base_url, Sentc.options.app_token, userIdentifier);
	}

	/**
	 * Prepare the data to done login process.
	 *
	 * prepare_login_server_output is the result of the prepareLoginStart function
	 *
	 * Send the auth key string to the server and use the master_key_encryption_key for the done login function
	 */
	public prepareLogin(userIdentifier: string, password: string, prepare_login_server_output: string)
	{
		const data = prepare_login(userIdentifier, password, prepare_login_server_output);

		return [data.get_auth_key(), data.get_master_key_encryption_key()];
	}

	/**
	 * Get and decrypt the user data from the done_login_server_output output
	 *
	 * prepare login is required
	 */
	public async doneLogin(userIdentifier: string, master_key_encryption_key: string, done_login_server_output: string)
	{
		const out = done_login(master_key_encryption_key, done_login_server_output);

		const userData: UserData = {
			private_key: out.get_private_key(),
			public_key: out.get_public_key(),
			sign_key: out.get_sign_key(),
			verify_key: out.get_verify_key(),
			exported_public_key: out.get_exported_public_key(),
			exported_verify_key: out.get_exported_verify_key(),
			jwt: out.get_jwt(),
			refresh_token: out.get_refresh_token(),
			user_id: out.get_id()
		};

		//save user data in indexeddb
		const storage = await Sentc.getStore();

		await Promise.all([
			storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier, userData),
			storage.set(USER_KEY_STORAGE_NAMES.actualUser, userIdentifier)
		]);

		return userData;
	}

	/**
	 * Log the user in
	 *
	 * Store all user data in the storage (e.g. Indexeddb)
	 *
	 * For a refresh token flow -> send the refresh token to your server and save it in a http only strict cookie
	 * Then the user is safe for xss and csrf attacks
	 *
	 */
	public async login(userIdentifier: string, password: string)
	{
		const out = await login(Sentc.options.base_url, Sentc.options.app_token, userIdentifier, password);

		const userData: UserData = {
			private_key: out.get_private_key(),
			public_key: out.get_public_key(),
			sign_key: out.get_sign_key(),
			verify_key: out.get_verify_key(),
			exported_public_key: out.get_exported_public_key(),
			exported_verify_key: out.get_exported_verify_key(),
			jwt: out.get_jwt(),
			refresh_token: out.get_refresh_token(),
			user_id: out.get_id()
		};

		const store_user_data = userData;

		if (Sentc.options.refresh.endpoint !== REFRESH_ENDPOINT.api) {
			//if the refresh token should not be stored on the client -> invalidates the stored refresh token
			//but just return the refresh token with the rest of the user data
			store_user_data.refresh_token = "";
		}

		//save user data in indexeddb
		const storage = await Sentc.getStore();

		await Promise.all([
			storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier, store_user_data),
			storage.set(USER_KEY_STORAGE_NAMES.actualUser, userIdentifier)
		]);

		return userData;
	}

	public static refreshJwt(old_jwt: string, refresh_token: string)
	{
		const options = this.options.refresh;

		if (options.endpoint === REFRESH_ENDPOINT.api) {
			//make the req directly to the api, via wasm
			return refresh_jwt(this.options.base_url, this.options.app_token, old_jwt, refresh_token);
		}

		//refresh token is not needed for the other options because the dev is responsible to send the refresh token
		// e.g. via http only cookie

		if (options.endpoint === REFRESH_ENDPOINT.cookie) {
			const headers = new Headers();
			headers.append("Authorization", "Bearer " + old_jwt);

			//make the req without a body because the token sits in cookie
			return fetch(options.endpoint_url, {
				method: "GET",
				credentials: "include",
				headers
			}).then((res) => {return res.text();});
		}
		
		if (options.endpoint === REFRESH_ENDPOINT.cookie_fn) {
			//make the req via the cookie fn, where the dev can define an own refresh flow
			return options.endpoint_fn(old_jwt);
		}

		throw new Error("No refresh option found");
	}

	//__________________________________________________________________________________________________________________

	public async resetPassword(newPassword: string)
	{
		//check if the user is logged in with a valid jwt and got the private keys
		const user = await Sentc.getActualUser(true);

		const decryptedPrivateKey = user.private_key;
		const decryptedSignKey = user.sign_key;

		return reset_password(
			Sentc.options.base_url,
			Sentc.options.app_token,
			user.jwt,
			newPassword,
			decryptedPrivateKey,
			decryptedSignKey
		);
	}

	public async changePassword(oldPassword:string, newPassword:string)
	{
		const user_check = await Sentc.getActualUser(false, true);

		if (!user_check) {
			//TODO err handling
			throw Error();
		}

		const username = user_check[1];

		return change_password(
			Sentc.options.base_url,
			Sentc.options.app_token,
			username,
			oldPassword,
			newPassword
		);
	}

	public async deleteUser(password: string)
	{
		const user = await Sentc.getActualUser(false, true);

		if (!user) {
			//TODO err handling
			throw Error();
		}

		return delete_user(
			Sentc.options.base_url,
			Sentc.options.app_token,
			user[1],
			password
		);
	}

	public async updateUser(newIdentifier: string)
	{
		const jwt = await Sentc.getJwt();

		return update_user(
			Sentc.options.base_url,
			Sentc.options.app_token,
			jwt,
			newIdentifier
		);
	}

	//__________________________________________________________________________________________________________________

	public static async getJwt()
	{
		//get the jwt from the store and check the exp
		const user = await this.getActualUser();

		return this.handleJwt(user.jwt, user.refresh_token);
	}

	private static async handleJwt(jwt: string, refresh_token: string)
	{
		const jwt_data = decode_jwt(jwt);

		const exp = jwt_data.get_exp();

		if (exp <= Date.now() + 30 * 1000) {
			//refresh even when the jwt is valid for 30 sec
			jwt = await this.refreshJwt(jwt, refresh_token);

			const [user_data, userIdentifier] = await this.getActualUser(false, true);

			user_data.jwt = jwt;

			const storage = await this.getStore();

			//save the user data with the new jwt
			await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier, user_data);
		}

		return jwt;
	}

	/**
	 * Get the actual used user data
	 *
	 * @throws Error
	 * when user is not set
	 */
	public static getActualUser(): Promise<UserData>;

	/**
	 * Get the actual user but with a valid jwt
	 * @param jwt
	 * @throws Error
	 * when user is not set or the jwt refresh failed
	 */
	public static getActualUser(jwt: true): Promise<UserData>;

	/**
	 * Get the actual used user and the username
	 *
	 * @param jwt
	 * @param username
	 * @throws Error
	 * when user not exists in the client
	 */
	public static getActualUser(jwt: false, username: true): Promise<[UserData, string]>;

	public static async getActualUser(jwt = false, username = false)
	{
		const storage = await this.getStore();

		const actualUser: string = await storage.getItem(USER_KEY_STORAGE_NAMES.actualUser);

		if (!actualUser) {
			//TODO error handling
			throw new Error();
		}

		const user = await this.getUser(actualUser);

		if (!user) {
			//TODO error handling
			throw new Error();
		}

		if (jwt) {
			user.jwt = await this.handleJwt(user.jwt, user.refresh_token);

			return user;
		}

		if (username) {
			return [user, actualUser];
		}

		return user;
	}

	public static async getUser(userIdentifier: string): Promise<UserData | false>
	{
		const storage = await this.getStore();

		const user = await storage.getItem(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier);

		if (!user) {
			return false;
		}

		return user;
	}

	public static async getUserPublicData(base_url: string, app_token: string, user_id: string)
	{
		const storage = await this.getStore();

		const store_key = USER_KEY_STORAGE_NAMES.userPublicData + "_id_" + user_id;

		const user = await storage.getItem(store_key);

		if (user) {
			return user;
		}

		const fetched_data = await user_fetch_public_data(base_url, app_token, user_id);

		if (!fetched_data) {
			//TODO error handling
			throw new Error();
		}

		await storage.set(store_key, fetched_data);

		return fetched_data;
	}

	public static async getUserPublicKeyData(base_url: string, app_token: string, user_id: string)
	{
		const storage = await this.getStore();

		const store_key = USER_KEY_STORAGE_NAMES.userPublicKey + "_id_" + user_id;

		const user = await storage.getItem(store_key);

		if (user) {
			return user;
		}

		const fetched_data = await user_fetch_public_key(base_url, app_token, user_id);

		if (!fetched_data) {
			//TODO error handling
			throw new Error();
		}

		await storage.set(store_key, fetched_data);

		return fetched_data;
	}

	public static async getUserVerifyKeyData(base_url: string, app_token: string, user_id: string)
	{
		const storage = await this.getStore();

		const store_key = USER_KEY_STORAGE_NAMES.userVerifyKey + "_id_" + user_id;

		const user = await storage.getItem(store_key);

		if (user) {
			return user;
		}

		const fetched_data = await user_fetch_verify_key(base_url, app_token, user_id);

		if (!fetched_data) {
			//TODO error handling
			throw new Error();
		}

		await storage.set(store_key, fetched_data);

		return fetched_data;
	}

	//__________________________________________________________________________________________________________________

	/**
	 * Fetch a group in the client. Won't work for server side rendering, use here the extract group data
	 *
	 * @param group_id
	 */
	public getGroup(group_id: string)
	{
		return getGroup(group_id, Sentc.options.base_url, Sentc.options.app_token);
	}

	public async getGroupInvites(last_fetched_item: GroupInviteListItem | null = null)
	{
		const jwt = await Sentc.getJwt();

		const last_fetched_time = last_fetched_item.time.toString() ?? "0";
		const last_id = last_fetched_item.group_id ?? "none";

		const out: GroupInviteListItem[] = await group_get_invites_for_user(
			Sentc.options.base_url,
			Sentc.options.app_token,
			jwt,
			last_fetched_time,
			last_id
		);

		return out;
	}

	public async acceptGroupInvite(group_id: string)
	{
		const jwt = await Sentc.getJwt();

		return group_accept_invite(
			Sentc.options.base_url,
			Sentc.options.app_token,
			jwt,
			group_id
		);
	}

	public async rejectGroupInvite(group_id: string)
	{
		const jwt = await Sentc.getJwt();

		return group_reject_invite(
			Sentc.options.base_url,
			Sentc.options.app_token,
			jwt,
			group_id
		);
	}

	//join req
	public async groupJoinRequest(group_id: string)
	{
		const jwt = await Sentc.getJwt();

		return group_join_req(
			Sentc.options.base_url,
			Sentc.options.app_token,
			jwt,
			group_id
		);
	}

	//__________________________________________________________________________________________________________________

	public async prepareGroupCreate()
	{
		const user = await Sentc.getActualUser();

		//important use the public key not the exported public key here!
		return group_prepare_create_group(user.public_key);
	}

	public async createGroup()
	{
		const user = await Sentc.getActualUser(true);

		return group_create_group(Sentc.options.base_url, Sentc.options.app_token, user.jwt, user.public_key);
	}
}