/**
 * @author Jörn Heinemann <joernheinemann@gmx.de>
 * @since 2022/07/16
 */

import init, {register, check_user_identifier_available, prepare_register, login, prepare_login_test, done_login_test} from "../pkg";
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
				base_url: options?.base_url ?? "123",	//TODO change base url
				app_token: options?.app_token
			});

			return this.sentc;
		}

		if (force) {
			//return a new instance with new options
			new Sentc({
				base_url: options?.base_url ?? "123",	//TODO change base url
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

	public prepareRegister(userIdentifier: string, password: string)
	{
		return prepare_register(userIdentifier, password);
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
		
		await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier, userData);

		return userData;
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

	public async loginTest(username: string, prep_server_out: string, done_login_server_out: string, userIdentifier: string, password: string)
	{
		const prep = prepare_login_test(username, password, prep_server_out);

		const out = done_login_test(prep.get_master_key_encryption_key(), done_login_server_out);

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

		const storage = await Sentc.getStore();

		await storage.set(USER_KEY_STORAGE_NAMES.userData + "_id_" + userIdentifier, userData);

		return userData;
	}
}