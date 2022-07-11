interface MasterKey
{
	master_key_alg: string,
	encrypted_master_key: string, //base64 encoded master key
	encrypted_master_key_alg: string,
}

interface KeyDerivedData
{
	derived_alg: string,
	client_random_value: string,
	hashed_authentication_key: string,

	//pub/pri encrypt decrypt
	public_key: string,
	encrypted_private_key: string,
	keypair_encrypt_alg: string,

	//sign/verify
	verify_key: string,
	encrypted_sign_key: string,
	keypair_sign_alg: string,
}

interface RegisterData
{
	master_key: MasterKey,
	derived: KeyDerivedData,
}

interface CryptoRawOutput
{
	head: string,
	data: Uint8Array
}