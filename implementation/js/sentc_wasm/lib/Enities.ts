export const enum USER_KEY_STORAGE_NAMES
{
	userData = "user_data",
	privateKey = "private_key",
	publicKey = "public_key",
	verifyKey = "verify_key",
	signKey = "sign_key"
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

