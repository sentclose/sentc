mod crypto;

#[derive(uniffi::Error, Debug)]
pub enum SentcError
{
	JSONError(String),
}

impl std::fmt::Display for SentcError
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
	{
		match self {
			Self::JSONError(e) => write!(f, "{e}"),
		}
	}
}

impl From<String> for SentcError
{
	fn from(value: String) -> Self
	{
		Self::JSONError(value)
	}
}

uniffi::setup_scaffolding!();
