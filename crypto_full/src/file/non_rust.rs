use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::file::{FileData, FilePartListItem};

pub type FileRes = Result<FileData, String>;
pub type FilePartRes = Result<Vec<FilePartListItem>, String>;
pub type ByteRes = Result<(Vec<u8>, String), String>;
pub type VoidRes = Result<(), String>;
pub type KeyRes = Result<String, String>;

pub type FileRegRes = Result<(String, String, Option<String>), String>;
