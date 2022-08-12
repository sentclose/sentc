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
	reset_password, update_user, change_password, delete_user
} from "../pkg";
import {USER_KEY_STORAGE_NAMES, UserData, UserId} from "./Enities";
import {ResCallBack, StorageFactory, StorageInterface} from "./core";

export interface StaticOptions {
	errCallBack: ResCallBack
}

export interface DynOptions {
	base_url?: string,
	app_token: string,
}

export interface SentcOptions {
	base_url?: string,
	app_token: string,
	storage?: StaticOptions
}

export class Sentc
{
	private static sentc: Sentc = null;

	private static init_storage = false;

	private static storage: StorageInterface;

	//@ts-ignore
	private static static_options: StaticOptions = {};

	// eslint-disable-next-line @typescript-eslint/no-empty-function
	private constructor(private options: DynOptions) {}
	
	public static async getStore()
	{
		//only init when needed
		if (this.init_storage) {
			//dont init again
			return this.storage;
		}

		this.storage = await StorageFactory.getStorage(this.static_options.errCallBack, "sentclose", "keys");

		this.init_storage = true;

		return this.storage;
	}

	public static async init(options: SentcOptions, force = false)
	{
		if (!this.sentc) {
			await init();	//init wasm

			let errCallback: ResCallBack;

			if (options?.storage?.errCallBack) {
				errCallback = options?.storage?.errCallBack;
			} else {
				errCallback = ({err, warn}) => {
					console.error(err);
					console.warn(warn);
				};
			}

			Sentc.static_options = {
				errCallBack: errCallback
			};

			this.sentc = new Sentc({
				base_url: options?.base_url ?? "http://127.0.0.1:3002",	//TODO change base url
				app_token: options?.app_token
			});

			return this.sentc;
		}

		if (force) {
			//return a new instance with new options
			new Sentc({
				base_url: options?.base_url ?? "http://127.0.0.1:3002",	//TODO change base url
				app_token: options?.app_token
			});
		}

		return this.sentc;
	}

	public checkUserIdentifierAvailable(userIdentifier: string)
	{
		if (userIdentifier === "") {
			return false;
		}

		return check_user_identifier_available(this.options.base_url, this.options.app_token, userIdentifier);
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

	public doneRegister(serverOutput: string)
	{
		return done_register(serverOutput);
	}

	public register(userIdentifier: string, password: string): Promise<UserId> | false
	{
		if (userIdentifier === "" || password === "") {
			return false;
		}

		return register(this.options.base_url, this.options.app_token, userIdentifier, password);
	}

	public async login(userIdentifier: string, password: string)
	{
		const out = await login(this.options.base_url, this.options.app_token, userIdentifier, password);

		const userData: UserData = {
			private_key: out.get_private_key(),
			public_key: out.get_public_key(),
			sign_key: out.get_sign_key(),
			verify_key: out.get_verify_key(),
			exported_public_key: out.get_exported_public_key(),
			exported_verify_key: out.get_exported_verify_key(),
			jwt: out.get_jwt(),
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

	public async resetPassword(newPassword: string)
	{
		//check if the user is logged in with a valid jwt and got the private keys
		const user = await this.getActualUser();

		if (!user) {
			//TODO err handling
			throw Error();
		}

		const jwt = await this.handleJwt(user.jwt);

		const decryptedPrivateKey = user.private_key;
		const decryptedSignKey = user.sign_key;

		return reset_password(
			this.options.base_url,
			this.options.app_token,
			jwt,
			newPassword,
			decryptedPrivateKey,
			decryptedSignKey
		);
	}

	public async changePassword(oldPassword:string, newPassword:string)
	{
		const user_check = await this.getActualUser(true);

		if (!user_check) {
			//TODO err handling
			throw Error();
		}

		const username = user_check[1];

		return change_password(
			this.options.base_url,
			this.options.app_token,
			username,
			oldPassword,
			newPassword
		);
	}

	public async deleteUser(password: string)
	{
		const user = await this.getActualUser(true);

		if (!user) {
			//TODO err handling
			throw Error();
		}

		return delete_user(
			this.options.base_url,
			this.options.app_token,
			user[1],
			password
		);
	}

	public async updateUser(newIdentifier: string)
	{
		const jwt = await this.getJwt();

		return update_user(
			this.options.base_url,
			this.options.app_token,
			jwt,
			newIdentifier
		);
	}

	//__________________________________________________________________________________________________________________

	public async getJwt()
	{
		//get the jwt from the store and check the exp
		const user = await this.getActualUser();

		if (!user) {
			//TODO err handling
			throw Error();
		}

		return this.handleJwt(user.jwt);
	}

	// eslint-disable-next-line require-await
	private async handleJwt(jwt: string)
	{
		const jwt_data = decode_jwt(jwt);

		const exp = jwt_data.get_exp();

		if (exp <= Date.now() + 30 * 1000) {
			//TODO do refresh request
		}

		return jwt;
	}

	private getActualUser(): Promise<UserData | false>;

	private getActualUser(username: boolean): Promise<[UserData, string] | false>;

	private async getActualUser(username = false)
	{
		const storage = await Sentc.getStore();

		const actualUser: string = await storage.getItem(USER_KEY_STORAGE_NAMES.actualUser);

		if (!actualUser) {
			return false;
		}

		if (username) {
			const user = await this.getUser(actualUser);

			if (!user) {
				return false;
			}

			return [user, actualUser];
		}

		return this.getUser(actualUser);
	}

	public async getUser(userIdentifier: string): Promise<UserData | false>
	{
		const storage = await Sentc.getStore();

		const user = await storage.getItem(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier);

		if (!user) {
			return false;
		}

		return user;
	}
}