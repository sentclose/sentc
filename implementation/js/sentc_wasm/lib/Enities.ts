type GeneralIdFormat = string;
export type UserId = GeneralIdFormat;

export const enum USER_KEY_STORAGE_NAMES
{
	userData = "user_data",
	actualUser = "actual_user",

	groupData = "group_data"
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

export interface GroupKey {
	private_group_key: string,
	public_group_key: string,
	group_key: string,
	time: number
}

export interface GroupData
{
	group_id: string,
	parent_group_id: string,
	rank: number,
	key_update:boolean,
	create_time: string,
	joined_time: string,
	keys: GroupKey[]
}

