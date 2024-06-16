pub(crate) mod file;
#[cfg(not(feature = "rust"))]
mod file_export;

pub use self::file::FileEncryptor;
#[cfg(feature = "rust")]
pub use self::file::*;
#[cfg(not(feature = "rust"))]
pub use self::file_export::*;
