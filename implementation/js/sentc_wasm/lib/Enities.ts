type GeneralIdFormat = string;
export type UserId = GeneralIdFormat;

export const enum USER_KEY_STORAGE_NAMES
{
	userData = "user_data",
	actualUser = "actual_user"
}

export interface UserData
{
	private_key:string,
	public_key: string,
	sign_key: string,
	verify_key: string,
	exported_public_key: string,
	exported_verify_key: string,
	jwt: string,
	refresh_token: string,
	user_id: string
}

export interface GroupData
{
	group_id: string,
	keys: {
		private_group_key: string,
		public_group_key: string,
		group_key: string
	}[]
}

