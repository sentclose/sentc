#![allow(clippy::too_many_arguments)]

use sentc_crypto::SdkError;

mod crypto;
mod file;
mod group;
mod user;

#[derive(uniffi::Error, Debug)]
pub enum SentcError
{
	JSONError
	{
		e: String
	},
}

impl std::fmt::Display for SentcError
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
	{
		match self {
			Self::JSONError {
				e,
			} => write!(f, "{e}"),
		}
	}
}

impl From<String> for SentcError
{
	fn from(e: String) -> Self
	{
		Self::JSONError {
			e,
		}
	}
}

impl From<SdkError> for SentcError
{
	fn from(value: SdkError) -> Self
	{
		Self::JSONError {
			e: value.into(),
		}
	}
}

uniffi::setup_scaffolding!();
