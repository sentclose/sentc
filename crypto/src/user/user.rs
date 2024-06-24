use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use core::marker::PhantomData;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use sentc_crypto_common::group::GroupKeyServerOutput;
use sentc_crypto_common::user::{
	DoneLoginServerOutput,
	KeyDerivedData,
	MasterKey,
	RegisterData,
	RegisterServerOutput,
	ResetPasswordData,
	UserDeviceDoneRegisterInput,
	UserDeviceRegisterInput,
	UserDeviceRegisterOutput,
	UserIdentifierAvailableServerInput,
	UserIdentifierAvailableServerOutput,
	UserPublicKeyData,
	UserVerifyKeyData,
	VerifyLoginOutput,
};
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_core::cryptomat::{DeriveMasterKeyForAuth, Pk, PwHash, SearchableKeyGen, SignKeyComposer, SortableKeyGen, StaticKeyPair};
use sentc_crypto_core::user as core_user;
use sentc_crypto_utils::cryptomat::{
	PkFromUserKeyWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKWrapper,
	SignKeyPairWrapper,
	SkWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::user::{DeviceKeyDataInt, UserPreVerifyLogin};
use sentc_crypto_utils::{client_random_value_to_string, hashed_authentication_key_to_string};

use crate::entities::user::{UserDataInt, UserKeyDataInt};
use crate::group::Group;
use crate::util::public::handle_server_response;
use crate::SdkError;

pub struct User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
{
	_sgen: PhantomData<SGen>,
	_st_gen: PhantomData<StGen>,
	_sign_gen: PhantomData<SignGen>,
	_search_gen: PhantomData<SearchGen>,
	_sort_gen: PhantomData<SortGen>,
	_sc: PhantomData<SC>,
	_st_c: PhantomData<StC>,
	_sign_c: PhantomData<SignC>,
	_search_c: PhantomData<SearchC>,
	_sort_c: PhantomData<SortC>,
	_pc: PhantomData<PC>,
	_vc: PhantomData<VC>,
	_pw: PhantomData<PwH>,
}

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
	User<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC, PwH>
where
	SGen: SymKeyGenWrapper,
	StGen: StaticKeyPairWrapper,
	SignGen: SignKeyPairWrapper,
	SearchGen: SearchableKeyGen,
	SortGen: SortableKeyGen,
	SC: SymKeyComposerWrapper,
	StC: StaticKeyComposerWrapper,
	SignC: SignComposerWrapper,
	SearchC: SearchableKeyComposerWrapper,
	SortC: SortableKeyComposerWrapper,
	PC: PkFromUserKeyWrapper,
	VC: VerifyKFromUserKeyWrapper,
	PwH: PwHash,
{
	pub fn register(user_identifier: &str, password: &str) -> Result<String, SdkError>
	{
		let register_out = Self::register_typed(user_identifier, password)?;

		//use always to string, even for rust feature enable because this data is for the server
		register_out
			.to_string()
			.map_err(|_| SdkError::JsonToStringFailed)
	}

	/**
	# Prepare the register input incl. keys
	 */
	pub fn register_typed(user_identifier: &str, password: &str) -> Result<RegisterData, SdkError>
	{
		let (device, raw_public_key) = Self::prepare_register_device_private_internally(user_identifier, password)?;

		//6. create the user group
		//6.1 get a "fake" public key from the register data for group create
		//the public key id will be set later after the registration on the server
		let group_public_key = StGen::pk_from_inner(raw_public_key, "non_registered".to_string());

		//6.2 create a group
		let (group, _, _) =
			Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::prepare_create_private_internally(
				&group_public_key,
				true,
			)?;

		Ok(RegisterData {
			device,
			group,
		})
	}

	fn prepare_register_device_private_internally(
		device_identifier: &str,
		password: &str,
	) -> Result<
		(
			UserDeviceRegisterInput,
			<<StGen as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::PublicKey,
		),
		SdkError,
	>
	{
		let out = core_user::register::<SGen::KeyGen, StGen::KeyGen, SignGen::KeyGen, PwH>(password)?;

		//transform the register output into json

		//1. encode the encrypted data to base64
		let encrypted_master_key = Base64::encode_string(&out.encrypted_master_key);
		let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
		let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

		//2. export the public keys (decrypt and verify) to a key format

		let public_key = StGen::pk_inner_to_pem(&out.public_key)?;

		let verify_key = SignGen::vk_inner_to_pem(&out.verify_key)?;

		//3. export the random value
		let client_random_value = client_random_value_to_string(&out.client_random_value);

		//4. export the hashed auth key (the first 16 bits)
		let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

		//5. create the structs
		let master_key = MasterKey {
			encrypted_master_key,
			master_key_alg: out.master_key_alg.to_string(),
			encrypted_master_key_alg: out.encrypted_master_key_alg.to_string(),
		};

		let derived = KeyDerivedData {
			public_key,
			verify_key,
			derived_alg: out.derived_alg.to_string(),
			client_random_value,
			encrypted_private_key,
			encrypted_sign_key,
			keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
			keypair_sign_alg: out.keypair_sign_alg.to_string(),
			hashed_authentication_key,
		};

		Ok((
			UserDeviceRegisterInput {
				master_key,
				derived,
				device_identifier: device_identifier.to_string(),
			},
			out.public_key, //needed for register
		))
	}

	/**
	Call this fn before the register device request in the new device.

	Transfer the output from this request to the active device to accept this device
	 */
	pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, SdkError>
	{
		let (device, _) = Self::prepare_register_device_private_internally(device_identifier, password)?;

		serde_json::to_string(&device).map_err(|_| SdkError::JsonToStringFailed)
	}

	/**
	Prepare the user group keys for the new device.

	Call this fn from the active device with the server output from register device

	Return the public key of the device, for the key session
	 */
	pub fn prepare_register_device(
		server_output: &str,
		group_keys: &[&impl SymKeyWrapper],
		key_session: bool,
	) -> Result<(String, UserPublicKeyData), SdkError>
	{
		let out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

		//no sig for device keys
		let exported_public_key = UserPublicKeyData {
			public_key_pem: out.public_key_string,
			public_key_alg: out.keypair_encrypt_alg,
			public_key_id: out.device_id,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let user_keys =
			Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::prepare_group_keys_for_new_member_typed(
				&exported_public_key,
				group_keys,
				key_session,
				None,
			)?;

		Ok((
			serde_json::to_string(&UserDeviceDoneRegisterInput {
				user_keys,
				token: out.token,
			})
			.map_err(|_| SdkError::JsonToStringFailed)?,
			exported_public_key,
		))
	}

	//______________________________________________________________________________________________

	/**
	# Starts the login process

	1. Get the auth key and the master key encryption key from the password.
	2. Send the auth key to the server to get the DoneLoginInput back
	 */
	pub fn prepare_login(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, String, PwH::DMK), SdkError>
	{
		Ok(sentc_crypto_utils::user::prepare_login::<PwH>(
			user_identifier,
			password,
			server_output,
		)?)
	}

	/**
	# finalize the login process

	1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private and sign keys, in pem exported public and verify keys
	2. decrypt the master key with the encryption key from @see prepare_login
	3. import the public and verify keys to the internal format
	 */
	pub fn done_login(
		master_key_encryption: &impl DeriveMasterKeyForAuth,
		auth_key: String,
		device_identifier: String,
		server_output: DoneLoginServerOutput,
	) -> Result<UserPreVerifyLogin<StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		Ok(sentc_crypto_utils::user::done_login::<StC, SignC>(
			master_key_encryption,
			auth_key,
			device_identifier,
			server_output,
		)?)
	}

	pub fn done_validate_mfa(
		master_key_encryption: &impl DeriveMasterKeyForAuth,
		auth_key: String,
		device_identifier: String,
		server_output: &str,
	) -> Result<UserPreVerifyLogin<StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		Ok(sentc_crypto_utils::user::done_validate_mfa::<StC, SignC>(
			master_key_encryption,
			auth_key,
			device_identifier,
			server_output,
		)?)
	}

	pub fn verify_login(
		server_output: &str,
		user_id: UserId,
		device_id: DeviceId,
		device_keys: DeviceKeyDataInt<StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>,
	) -> Result<UserDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let server_output: VerifyLoginOutput = handle_server_response(server_output)?;

		//export the hmac keys to decrypt it later
		Ok(UserDataInt {
			user_keys: server_output
				.user_keys
				.into_iter()
				.map(|i| Self::done_login_internally_with_user_out(&device_keys.private_key, i))
				.collect::<Result<_, _>>()?,
			hmac_keys: server_output.hmac_keys,
			device_keys,
			jwt: server_output.jwt,
			refresh_token: server_output.refresh_token,
			user_id,
			device_id,
		})
	}

	pub fn done_key_fetch(
		private_key: &impl SkWrapper,
		server_output: &str,
	) -> Result<UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let out: GroupKeyServerOutput = handle_server_response(server_output)?;

		let key = Self::done_login_internally_with_user_out(private_key, out)?;

		Ok(key)
	}

	/**
	# Get the user keys from the user group

	Decrypt it like group decrypt keys (which is used here)
	But decrypt the sign key too

	It can be immediately decrypt because the there is only one device key row not multiple like for group
	 */
	fn done_login_internally_with_user_out(
		private_key: &impl SkWrapper,
		user_group_key: GroupKeyServerOutput,
	) -> Result<UserKeyDataInt<SC::SymmetricKeyWrapper, StC::SkWrapper, StC::PkWrapper, SignC::SignKWrapper, SignC::VerifyKWrapper>, SdkError>
	{
		let keypair_sign_id = user_group_key.keypair_sign_id.to_owned();
		let keypair_sign_alg = user_group_key.keypair_sign_alg.to_owned();
		let verify_key = user_group_key.verify_key.to_owned();

		//now get the verify key
		let (keys, sign_key, verify_key, exported_verify_key) = match (
			&user_group_key.encrypted_sign_key,
			verify_key,
			keypair_sign_alg,
			keypair_sign_id,
		) {
			(Some(encrypted_sign_key), Some(server_verify_key), Some(keypair_sign_alg), Some(keypair_sign_id)) => {
				//handle it, only for user group

				//get the sign key first to not use to owned for it because we only need the ref here
				let encrypted_sign_key = Base64::decode_vec(encrypted_sign_key).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

				let keys = Group::<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>::decrypt_group_keys(
					private_key,
					user_group_key,
				)?;

				let sign_key = SignC::Composer::decrypt_by_master_key(keys.group_key.get_key(), &encrypted_sign_key, &keypair_sign_alg)?;
				let sign_key = SignC::sk_from_inner(sign_key, keypair_sign_id.clone());

				let verify_key = SignC::vk_from_pem(&server_verify_key, &keypair_sign_alg, keypair_sign_id.clone())?;

				let exported_verify_key = UserVerifyKeyData {
					verify_key_pem: server_verify_key,
					verify_key_alg: keypair_sign_alg,
					verify_key_id: keypair_sign_id,
				};

				(keys, sign_key, verify_key, exported_verify_key)
			},
			_ => return Err(SdkError::LoginServerOutputWrong),
		};

		Ok(UserKeyDataInt {
			group_key: keys.group_key,
			private_key: keys.private_group_key,
			public_key: keys.public_group_key,
			time: keys.time,
			sign_key,
			verify_key,
			exported_public_key: keys.exported_public_key,
			exported_verify_key,
		})
	}

	/**
	Make the prepare and done login req.

	- prep login to get the salt
	- done login to get the encrypted master key, because this key is never stored on the device
	 */
	pub fn change_password(
		old_pw: &str,
		new_pw: &str,
		server_output_prep_login: &str,
		server_output_done_login: DoneLoginServerOutput,
	) -> Result<String, SdkError>
	{
		Ok(sentc_crypto_utils::user::change_password::<PwH>(
			old_pw,
			new_pw,
			server_output_prep_login,
			server_output_done_login,
		)?)
	}

	pub fn reset_password(
		new_password: &str,
		decrypted_private_key: &impl SkWrapper,
		decrypted_sign_key: &impl SignKWrapper,
	) -> Result<String, SdkError>
	{
		let out = core_user::password_reset::<SGen::KeyGen, PwH>(
			new_password,
			decrypted_private_key.get_key(),
			decrypted_sign_key.get_key(),
		)?;

		let encrypted_master_key = Base64::encode_string(&out.encrypted_master_key);
		let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
		let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

		//prepare for the server
		let client_random_value = client_random_value_to_string(&out.client_random_value);
		let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

		let master_key = MasterKey {
			encrypted_master_key,
			master_key_alg: out.master_key_alg.to_string(),
			encrypted_master_key_alg: out.encrypted_master_key_alg.to_string(),
		};

		let data = ResetPasswordData {
			client_random_value,
			hashed_authentication_key,
			master_key,
			derived_alg: out.derived_alg.to_string(),
			encrypted_sign_key,
			encrypted_private_key,
		};

		data.to_string().map_err(|_| SdkError::JsonToStringFailed)
	}

	/**
	Create a safety number

	When creating a combined number than use always the user id which comes first in the alphabet as the first user
	 */
	pub fn create_safety_number(
		verify_key_1: &UserVerifyKeyData,
		user_id_1: &str,
		verify_key_2: Option<&UserVerifyKeyData>,
		user_id_2: Option<&str>,
	) -> Result<String, SdkError>
	{
		let verify_key_1 = SignC::vk_inner_from_pem(&verify_key_1.verify_key_pem, &verify_key_1.verify_key_alg)?;

		let number = match (verify_key_2, user_id_2) {
			(Some(k), Some(id)) => {
				let verify_key_2 = SignC::vk_inner_from_pem(&k.verify_key_pem, &k.verify_key_alg)?;

				if id > user_id_1 {
					//if the user id 1 comes first in the alphabet
					core_user::safety_number(&verify_key_1, user_id_1, Some(&verify_key_2), Some(id))
				} else {
					core_user::safety_number(&verify_key_2, id, Some(&verify_key_1), Some(user_id_1))
				}
			},
			_ => core_user::safety_number(&verify_key_1, user_id_1, None, None),
		};

		Ok(Base64UrlUnpadded::encode_string(&number))
	}

	pub fn verify_user_public_key(verify_key: &UserVerifyKeyData, public_key: &UserPublicKeyData) -> Result<bool, SdkError>
	{
		let raw_verify_key = SignC::vk_inner_from_pem(&verify_key.verify_key_pem, &verify_key.verify_key_alg)?;

		let sig = match &public_key.public_key_sig {
			Some(s) => s,
			None => {
				return Ok(false);
			},
		};

		let sig = SignC::sig_from_string(sig, &verify_key.verify_key_alg)?;

		let public_key = StC::pk_inner_from_pem(&public_key.public_key_pem, &public_key.public_key_alg)?;

		Ok(public_key.verify_public_key(&raw_verify_key, &sig)?)
	}
}

/**
# Prepare the server input for the check
 */
pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, SdkError>
{
	UserIdentifierAvailableServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkError::JsonToStringFailed)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, SdkError>
{
	let server_output: UserIdentifierAvailableServerOutput = handle_server_response(server_output)?;

	Ok(server_output.available)
}

pub fn generate_user_register_data() -> Result<(String, String), SdkError>
{
	let (identifier, password) = sentc_crypto_core::generate_user_register_data()?;

	let encoded_identifier = Base64UrlUnpadded::encode_string(&identifier);
	let encoded_password = Base64UrlUnpadded::encode_string(&password);

	Ok((encoded_identifier, encoded_password))
}

pub fn done_register(server_output: &str) -> Result<UserId, SdkError>
{
	let out: RegisterServerOutput = handle_server_response(server_output)?;

	Ok(out.user_id)
}

/**
Call this fn after the register device request in the new device to get the token.

This is just a check if the response was successful
 */
pub fn done_register_device_start(server_output: &str) -> Result<(), SdkError>
{
	let _out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

	Ok(())
}

//__________________________________________________________________________________________________

/**
# prepare the data for the server req

 */
pub fn prepare_login_start(user_identifier: &str) -> Result<String, SdkError>
{
	Ok(sentc_crypto_utils::user::prepare_login_start(user_identifier)?)
}

//__________________________________________________________________________________________________

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, SdkError>
{
	Ok(sentc_crypto_utils::user::prepare_user_identifier_update(
		user_identifier,
	)?)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, SdkError>
{
	Ok(sentc_crypto_utils::user::prepare_refresh_jwt(refresh_token)?)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;

	use sentc_crypto_common::group::CreateData;
	use sentc_crypto_common::user::{
		ChangePasswordData,
		RegisterData,
		UserDeviceDoneRegisterInput,
		UserDeviceRegisterInput,
		UserDeviceRegisterOutput,
	};
	use sentc_crypto_common::ServerOutput;
	use serde_json::to_string;

	use super::*;
	use crate::user::test_fn::{create_user, simulate_server_done_login, simulate_server_prepare_login, simulate_verify_login, TestUser};

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = TestUser::register(username, password).unwrap();

		std::println!("rust: {}", out);
	}

	#[test]
	fn test_register_with_generated_data()
	{
		let (username, password) = generate_user_register_data().unwrap();

		TestUser::register(&username, &password).unwrap();
	}

	#[test]
	fn test_register_and_login()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out_string = TestUser::register(username, password).unwrap();

		let out = RegisterData::from_string(&out_string).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_, auth_key, master_key_encryption_key) = TestUser::prepare_login(username, password, &server_output).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = TestUser::done_login(
			&master_key_encryption_key,
			auth_key,
			username.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(RegisterData::from_string(&out_string).unwrap(), &login_out.challenge);
		let _out = TestUser::verify_login(
			&server_output,
			login_out.user_id,
			login_out.device_id,
			login_out.device_keys,
		)
		.unwrap();
	}

	#[test]
	fn test_change_password()
	{
		let username = "admin";
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = TestUser::register(username, password).unwrap();

		let out_new = RegisterData::from_string(out.as_str()).unwrap();
		let out_old = RegisterData::from_string(out.as_str()).unwrap();

		let prep_server_output = simulate_server_prepare_login(&out_new.device.derived);
		let done_server_output = simulate_server_done_login(out_new);

		let pw_change_out = TestUser::change_password(password, new_password, &prep_server_output, done_server_output).unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_str()).unwrap();

		assert_ne!(
			pw_change_out.new_client_random_value,
			out_old.device.derived.client_random_value
		);

		assert_ne!(
			pw_change_out.new_encrypted_master_key,
			out_old.device.master_key.encrypted_master_key
		);
	}

	#[test]
	fn test_new_device()
	{
		//1. register the main device
		let out_string = TestUser::register("hello", "1234").unwrap();
		let out = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);
		let (_, auth_key, master_key_encryption_key) = TestUser::prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let done_login_out = TestUser::done_login(
			&master_key_encryption_key, //the value comes from prepare login
			auth_key,
			"hello".to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(
			RegisterData::from_string(&out_string).unwrap(),
			&done_login_out.challenge,
		);
		let user = TestUser::verify_login(
			&server_output,
			done_login_out.user_id,
			done_login_out.device_id,
			done_login_out.device_keys,
		)
		.unwrap();

		//2. prepare the device register
		let device_id = "hello_device";
		let device_pw = "12345";

		let server_input = TestUser::prepare_register_device_start(device_id, device_pw).unwrap();

		//3. simulate server
		let input: UserDeviceRegisterInput = serde_json::from_str(&server_input).unwrap();

		//4. server output
		let server_output = UserDeviceRegisterOutput {
			device_id: "abc".to_string(),
			token: "1234567890".to_string(),
			device_identifier: device_id.to_string(),
			public_key_string: input.derived.public_key.to_string(),
			keypair_encrypt_alg: input.derived.keypair_encrypt_alg.to_string(),
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_output),
		};

		let server_output = to_string(&server_output).unwrap();

		//5. check the server output
		done_register_device_start(&server_output).unwrap();

		//6. register the device with the main device

		let (out, _) = TestUser::prepare_register_device(&server_output, &[&user.user_keys[0].group_key], false).unwrap();

		let out: UserDeviceDoneRegisterInput = serde_json::from_str(&out).unwrap();
		let user_keys = &out.user_keys.keys[0];

		//7. check login with new device
		let out_new_device = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&input.derived);
		let (_, auth_key, master_key_encryption_key) = TestUser::prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let new_device_register_data = to_string(&RegisterData {
			device: input,
			group: CreateData {
				encrypted_group_key: user_keys.encrypted_group_key.to_string(),
				group_key_alg: out_new_device.group.group_key_alg,
				encrypted_group_key_alg: user_keys.encrypted_alg.to_string(),

				//private and sign key are encrypted by group key and for all device the same
				encrypted_private_group_key: out_new_device.group.encrypted_private_group_key,
				public_group_key: out_new_device.group.public_group_key,
				keypair_encrypt_alg: out_new_device.group.keypair_encrypt_alg,
				creator_public_key_id: "abc".to_string(),
				encrypted_hmac_key: out_new_device.group.encrypted_hmac_key,
				encrypted_hmac_alg: out_new_device.group.encrypted_hmac_alg,
				encrypted_sortable_key: out_new_device.group.encrypted_sortable_key,
				encrypted_sortable_alg: out_new_device.group.encrypted_sortable_alg,
				encrypted_sign_key: out_new_device.group.encrypted_sign_key,
				verify_key: out_new_device.group.verify_key,
				keypair_sign_alg: out_new_device.group.keypair_sign_alg,
				public_key_sig: out_new_device.group.public_key_sig,
			},
		})
		.unwrap();

		let server_output = simulate_server_done_login(serde_json::from_str(&new_device_register_data).unwrap());

		let new_device_data = TestUser::done_login(
			&master_key_encryption_key,
			auth_key,
			device_id.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(
			serde_json::from_str(&new_device_register_data).unwrap(),
			&new_device_data.challenge,
		);

		let new_device_data = TestUser::verify_login(
			&server_output,
			new_device_data.user_id,
			new_device_data.device_id,
			new_device_data.device_keys,
		)
		.unwrap();

		assert_eq!(
			user.user_keys[0].group_key.key.as_ref(),
			new_device_data.user_keys[0].group_key.key.as_ref()
		);
	}

	#[test]
	fn test_safety_number()
	{
		//use other ids to compare equal
		let user_1 = create_user();
		let user_1_id = "abc1";
		let user_2 = create_user();
		let user_2_id = "abc2";
		let user_3 = create_user();
		let user_3_id = "abc3";

		let _number_single = TestUser::create_safety_number(&user_1.user_keys[0].exported_verify_key, &user_1.user_id, None, None).unwrap();

		let number = TestUser::create_safety_number(
			&user_1.user_keys[0].exported_verify_key,
			user_1_id,
			Some(&user_2.user_keys[0].exported_verify_key),
			Some(user_2_id),
		)
		.unwrap();
		let number_2 = TestUser::create_safety_number(
			&user_2.user_keys[0].exported_verify_key,
			user_2_id,
			Some(&user_1.user_keys[0].exported_verify_key),
			Some(user_1_id),
		)
		.unwrap();

		assert_eq!(number, number_2);

		let number_3 = TestUser::create_safety_number(
			&user_3.user_keys[0].exported_verify_key,
			user_3_id,
			Some(&user_1.user_keys[0].exported_verify_key),
			Some(user_1_id),
		)
		.unwrap();

		assert_ne!(number, number_3);
	}

	#[test]
	fn test_verify_public_key()
	{
		let user_1 = create_user();

		let verify = TestUser::verify_user_public_key(
			&user_1.user_keys[0].exported_verify_key,
			&user_1.user_keys[0].exported_public_key,
		)
		.unwrap();

		assert!(verify);
	}
}
