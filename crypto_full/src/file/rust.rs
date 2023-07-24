use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::sdk_core::SymKey;
use sentc_crypto::SdkError;
use sentc_crypto_common::file::{FileData, FilePartListItem};

pub type FileRes = Result<FileData, SdkError>;
pub type FilePartRes = Result<Vec<FilePartListItem>, SdkError>;
pub type ByteRes = Result<(Vec<u8>, SymKey), SdkError>;
pub type VoidRes = Result<(), SdkError>;
pub type KeyRes = Result<SymKey, SdkError>;

pub type FileRegRes = Result<(String, String, Option<String>), SdkError>;
