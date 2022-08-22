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
	user_fetch_public_key,
	user_fetch_public_data,
	user_fetch_verify_key,
	prepare_login_start,
	prepare_login,
	done_login, refresh_jwt,
	init_user,
	InitInput
} from "sentc_wasm";
import {USER_KEY_STORAGE_NAMES, UserData, UserId} from "./Enities";
import {ResCallBack, StorageFactory, StorageInterface} from "./core";
import {User} from "./User";

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
	storage?: StorageOptions,
	wasm_path?: InitInput | Promise<InitInput>
}

export class Sentc
{
	private static init_client = false;

	private static init_storage = false;

	private static storage: StorageInterface;

	//@ts-ignore
	private static options: SentcOptions = {};
	
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

	public static async init(options: SentcOptions): Promise<User | undefined>
	{
		if (this.init_client) {
			return this.getActualUser(true);
		}

		await init(options.wasm_path);	//init wasm

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

		try {
			const [user, username] = await this.getActualUser(false, true);

			if (refresh?.endpoint === REFRESH_ENDPOINT.api) {
				//if refresh over api -> then do the init
				const out = await init_user(options.base_url, options.app_token, user.user_data.jwt, user.user_data.refresh_token);

				//save the invites if we fetched them from init request
				user.user_data.jwt = out.get_jwt();
				user.group_invites = out.get_invites();
			} else {
				//if refresh over cookie -> do normal refresh jwt
				await user.getJwt();
			}

			const storage = await this.getStore();

			//save the user data with the new jwt
			await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + username, user.user_data);

			this.init_client = true;

			return user;
		} catch (e) {
			//user was not logged in -> do nothing
			this.init_client = true;
		}
	}

	public static checkUserIdentifierAvailable(userIdentifier: string)
	{
		if (userIdentifier === "") {
			return false;
		}

		return check_user_identifier_available(Sentc.options.base_url, Sentc.options.app_token, userIdentifier);
	}

	public static prepareCheckUserIdentifierAvailable(userIdentifier: string)
	{
		if (userIdentifier === "") {
			return false;
		}

		return prepare_check_user_identifier_available(userIdentifier);
	}

	public static doneCheckUserIdentifierAvailable(serverOutput: string)
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
	public static prepareRegister(userIdentifier: string, password: string)
	{
		return prepare_register(userIdentifier, password);
	}

	/**
	 * Validates the register output from the api when using prepare register function
	 *
	 * @param serverOutput
	 */
	public static doneRegister(serverOutput: string)
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
	public static register(userIdentifier: string, password: string): Promise<UserId> | false
	{
		if (userIdentifier === "" || password === "") {
			return false;
		}

		return register(Sentc.options.base_url, Sentc.options.app_token, userIdentifier, password);
	}

	/**
	 * Make the first login request to get the salt
	 */
	public static prepareLoginStart(userIdentifier: string)
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
	public static prepareLogin(userIdentifier: string, password: string, prepare_login_server_output: string)
	{
		const data = prepare_login(userIdentifier, password, prepare_login_server_output);

		return [data.get_auth_key(), data.get_master_key_encryption_key()];
	}

	/**
	 * Get and decrypt the user data from the done_login_server_output output
	 *
	 * prepare login is required
	 */
	public static async doneLogin(userIdentifier: string, master_key_encryption_key: string, done_login_server_output: string)
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

		return new User(Sentc.options.base_url, Sentc.options.app_token, userData, userIdentifier);
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
	public static async login(userIdentifier: string, password: string)
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

		return new User(Sentc.options.base_url, Sentc.options.app_token, userData, userIdentifier);
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

	/**
	 * Get the actual used user data
	 *
	 * @throws Error
	 * when user is not set
	 */
	public static getActualUser(): Promise<User>;

	/**
	 * Get the actual user but with a valid jwt
	 * @param jwt
	 * @throws Error
	 * when user is not set or the jwt refresh failed
	 */
	public static getActualUser(jwt: true): Promise<User>;

	/**
	 * Get the actual used user and the username
	 *
	 * @param jwt
	 * @param username
	 * @throws Error
	 * when user not exists in the client
	 */
	public static getActualUser(jwt: false, username: true): Promise<[User, string]>;

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
			await user.getJwt();

			return user;
		}

		if (username) {
			return [user, actualUser];
		}

		return user;
	}

	public static async getUser(userIdentifier: string): Promise<User | false>
	{
		const storage = await this.getStore();

		const user = await storage.getItem(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier);

		if (!user) {
			return false;
		}

		return new User(this.options.base_url, this.options.app_token, user, userIdentifier);
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

	public static async getUserPublicKeyData(base_url: string, app_token: string, user_id: string): Promise<{key: string, id: string}>
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

		const key = fetched_data.get_public_key();
		const id = fetched_data.get_public_key_id();

		const returns = {key, id};

		await storage.set(store_key, returns);

		return returns;
	}

	public static async getUserVerifyKeyData(base_url: string, app_token: string, user_id: string): Promise<{key: string, id: string}>
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

		const key = fetched_data.get_verify_key();
		const id = fetched_data.get_verify_key_id();

		const returns = {key, id};
		
		await storage.set(store_key, returns);

		return returns;
	}
}