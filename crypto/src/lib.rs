mod alg;
mod error;

pub use self::alg::asym::{AsymKeyOutput, Pk, Sk};
pub use self::alg::pw_hash::{ClientRandomValue, DeriveKeyOutput, HashedAuthenticationKey, MasterKeyInfo};
pub use self::alg::sym::{SymKey, SymKeyOutput};

pub fn aes() -> String
{
	//aes
	aes_intern()
}

fn aes_intern() -> String
{
	let test = "plaintext message";
	let test2 = "plaintext message2";

	let res = alg::sym::aes_gcm::generate_and_encrypt(test.as_ref());

	let (output, encrypted) = match res {
		Err(e) => return format!("Error for encrypt test 1: {:?}", e),
		Ok(v) => v,
	};

	let res = alg::sym::aes_gcm::encrypt(&output.key, test2.as_ref());

	let encrypted2 = match res {
		Err(e) => return format!("Error for encrypt test 2: {:?}", e),
		Ok(v) => v,
	};

	//decrypt
	let res = alg::sym::aes_gcm::decrypt(&output.key, &encrypted);

	let decrypted = match res {
		Err(e) => return format!("Error for decrypt test 1: {:?}", e),
		Ok(v) => v,
	};

	let res = alg::sym::aes_gcm::decrypt(&output.key, &encrypted2);

	let decrypted2 = match res {
		Err(e) => return format!("Error for decrypt test 2: {:?}", e),
		Ok(v) => v,
	};

	assert_eq!(&decrypted, b"plaintext message");
	assert_eq!(&decrypted2, b"plaintext message2");

	let one = std::str::from_utf8(&decrypted).unwrap().to_owned();
	let two = std::str::from_utf8(&decrypted2).unwrap();

	one + " " + two
}

pub fn ecdh() -> String
{
	// Alice
	//let (alice_secret, alice_pk) = alg::asym::ecies::generate_static_keypair();

	// Bob
	let bob_out = alg::asym::ecies::generate_static_keypair();

	let bob_secret = bob_out.sk;
	let bob_pk = bob_out.pk;

	//Alice create a msg for Bob's public key
	let alice_msg = "Hello Bob";
	let alice_encrypted = alg::asym::ecies::encrypt(&bob_pk, alice_msg.as_ref()).unwrap();

	//Bob decrypt it with his own private key
	let bob_decrypt = alg::asym::ecies::decrypt(&bob_secret, &alice_encrypted).unwrap();
	let bob_msg = std::str::from_utf8(&bob_decrypt).unwrap();

	assert_eq!(bob_msg, alice_msg);

	alice_msg.to_string() + " " + bob_msg
}

pub fn argon() -> String
{
	let master_key = alg::sym::aes_gcm::generate_key().unwrap();

	let key = match master_key.key {
		SymKey::Aes(k) => k,
	};

	let out = alg::pw_hash::argon2::derived_keys_from_password(b"abc", &key).unwrap();

	let encrypted_master_key = out.master_key_info.encrypted_master_key;

	base64::encode(encrypted_master_key)
}

pub fn argon_pw_encrypt() -> String
{
	let test = "plaintext message";

	//encrypt a value with a password, in prod this might be the key of the content
	let (aes_key_for_encrypt, salt) = alg::pw_hash::argon2::password_to_encrypt(b"my fancy password").unwrap();

	let encrypted = alg::sym::aes_gcm::encrypt_with_generated_key(&aes_key_for_encrypt, test.as_ref()).unwrap();

	//decrypt a value with password
	let aes_key_for_decrypt = alg::pw_hash::argon2::password_to_decrypt(b"my fancy password", &salt).unwrap();

	let decrypted = alg::sym::aes_gcm::decrypt_with_generated_key(&aes_key_for_decrypt, &encrypted).unwrap();

	let str = std::str::from_utf8(&decrypted).unwrap();

	assert_eq!(str, test);

	str.to_owned()
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_aes()
	{
		let str = aes();

		assert_eq!(str, "plaintext message plaintext message2");
	}

	#[test]
	fn test_ecdh()
	{
		let str = ecdh();

		assert_eq!(str, "Hello Bob Hello Bob");
	}

	#[test]
	fn test_register()
	{
		let str = argon();

		assert_ne!(str.len(), 0);
	}

	#[test]
	fn test_pw_encrypt()
	{
		let str = argon_pw_encrypt();

		assert_eq!(str, "plaintext message");
	}
}
