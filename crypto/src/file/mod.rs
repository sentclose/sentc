pub(crate) mod file;
#[cfg(feature = "export")]
mod file_export;

pub use self::file::FileEncryptor;
#[cfg(not(feature = "export"))]
pub use self::file::*;
#[cfg(feature = "export")]
pub use self::file_export::*;
