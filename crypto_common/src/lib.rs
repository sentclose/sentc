#![no_std]

extern crate alloc;

use alloc::string::String;

pub mod crypto;
pub mod group;
pub mod user;

type GeneralIdFormat = String;
pub type GroupId = GeneralIdFormat;
pub type UserId = GeneralIdFormat;
pub type EncryptionKeyPairId = GeneralIdFormat;
pub type SignKeyPairId = GeneralIdFormat;
pub type SymKeyId = GeneralIdFormat;
