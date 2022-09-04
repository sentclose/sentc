use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::file::{FileData, FilePartListItem};

use crate::error::SdkFullError;

pub type FileRes = Result<FileData, SdkFullError>;
pub type FilePartRes = Result<Vec<FilePartListItem>, SdkFullError>;
pub type ByteRes = Result<Vec<u8>, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;

pub type FileRegRes = Result<(String, String, Option<String>), SdkFullError>;
