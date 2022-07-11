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

interface PrepareLoginData {
	auth_key: string,
	master_key_encryption_key: {[alg: string]: string}
}

interface KeyData
{
	private_key: {
		[alg: string]: {
			key: string,
			key_id: "abc"
		}
	},
	public_key: {
		[alg: string]: {
			key: "3S/9aOAYyL/IMzNvxUdqi2L5G79W+Z0j+YCXwleJQQ0=",
			key_id: "abc"
		}
	},
	sign_key: {
		[alg: string]: {
			key: "cF+UCmXdrcJX+ratF3l+ThCGl94hVJLdJ2u/QoSCh0Q=",
			key_id: "dfg"
		}
	},
	verify_key: {
		[alg: string]: {
			key: "Qrz/TApH37BgjQlskJ1XlXAMAv7GzlVxtT904WZz+as=",
			key_id: "dfg"
		}
	}
}
