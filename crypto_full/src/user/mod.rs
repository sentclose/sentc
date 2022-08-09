#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

pub use sentc_crypto::KeyData;

#[cfg(not(feature = "rust"))]
pub use self::non_rust::{change_password, check_user_identifier_available, done_login, login, prepare_login_start, register};
#[cfg(feature = "rust")]
pub use self::rust::login;
