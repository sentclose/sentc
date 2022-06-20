use sendclose_crypto::{aes, argon, ecdh};

pub fn aes_test() -> String
{
	aes()
}

pub fn ed_test() -> String
{
	ecdh()
}

pub fn argon_test() -> String
{
	argon()
}
