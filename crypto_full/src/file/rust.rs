use alloc::vec::Vec;

use sentc_crypto_common::file::FileData;

use crate::error::SdkFullError;

pub type FileRes = Result<FileData, SdkFullError>;
pub type ByteRes = Result<Vec<u8>, SdkFullError>;
