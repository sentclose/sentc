type GeneralIdFormat = string;
export type UserId = GeneralIdFormat;

export const enum USER_KEY_STORAGE_NAMES
{
	userData = "user_data",
	actualUser = "actual_user",

	userPublicData = "user_public_data",
	userPublicKey = "user_public_key",
	userVerifyKey = "user_verify_key",

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
	time: string,
	group_key_id: string
}

export interface GroupOutDataKeys {
	private_key_id: string,
	key_data: string
}

export interface GroupData
{
	group_id: string,
	parent_group_id: string,
	from_parent: boolean,	//describe if this group was fetched by parent group or normal fetch
	rank: number,
	key_update:boolean,
	create_time: string,
	joined_time: string,
	keys: GroupKey[],
	key_map: Map<string, number>	//save the index of the key to this key id
}

export interface GroupInviteListItem
{
	group_id: string,
	time: number
}

export interface GroupJoinReqListItem
{
	user_id: string,
	time: number
}

export interface GroupKeyRotationOut
{
	pre_group_key_id: string,
	server_output: string,
	encrypted_eph_key_key_id: string
}

export interface KeyRotationInput {
	encrypted_ephemeral_key_by_group_key_and_public_key: string,
	encrypted_group_key_by_ephemeral: string,
	ephemeral_alg: string,
	encrypted_eph_key_key_id: string, //the public key id which was used to encrypt the eph key on the server.
	previous_group_key_id: string,
	time: string,
	new_group_key_id: string,
}

export interface GroupUserListItem {
	user_id: string,
	rank: number,
	joined_time: number,
}

//______________________________________________________________________________________________________________________

export interface SignHead {
	id: string,
	alg: string
}

export interface CryptoHead {
	id: string,
	sign: SignHead | undefined
}

export interface CryptoRawOutput
{
	head: string,
	data: Uint8Array
}

