#[macro_export]
macro_rules! wrapper_impl {
	($trait_impl:ident, $name:ident, $inner:ident) => {
		impl $trait_impl for $name
		{
			type Inner = $inner;

			fn get_id(&self) -> &str
			{
				&self.key_id
			}

			fn get_key(&self) -> &Self::Inner
			{
				&self.key
			}
		}
	};
}

#[macro_export]
macro_rules! to_string_impl {
	($st:ty,$t:ty) => {
		impl $crate::cryptomat::KeyToString for $st
		{
			fn to_string(self) -> Result<String, $crate::error::SdkUtilError>
			{
				serde_json::to_string(&Into::<$t>::into(self)).map_err(|_e| $crate::error::SdkUtilError::JsonToStringFailed)
			}
		}
	};
}

#[macro_export]
macro_rules! to_string_try_impl {
	($st:ty,$t:ty) => {
		impl $crate::cryptomat::KeyToString for $st
		{
			fn to_string(self) -> Result<String, $crate::error::SdkUtilError>
			{
				serde_json::to_string(&TryInto::<$t>::try_into(self)?).map_err(|_e| $crate::error::SdkUtilError::JsonToStringFailed)
			}
		}
	};
}

#[macro_export]
macro_rules! from_string_impl {
	($st:ty,$t:ty) => {
		impl FromStr for $st
		{
			type Err = $crate::error::SdkUtilError;

			fn from_str(s: &str) -> Result<Self, Self::Err>
			{
				let key: $t = serde_json::from_str(s).map_err(|_| $crate::error::SdkUtilError::ImportKeyFailed)?;

				key.try_into()
			}
		}
	};
}

//__________________________________________________________________________________________________

#[macro_export]
macro_rules! sym_key_gen_self {
	($st:ty,$core:ty) => {
		impl $crate::cryptomat::SymKeyGenWrapper for $st
		{
			type SymmetricKeyWrapper = Self;
			type KeyGen = $core;

			fn from_inner(
				inner: <<Self as $crate::cryptomat::SymKeyGenWrapper>::KeyGen as sentc_crypto_core::cryptomat::SymKeyGen>::SymmetricKey,
				id: String,
			) -> Self::SymmetricKeyWrapper
			{
				Self {
					key: inner,
					key_id: id,
				}
			}
		}
	};
}

#[macro_export]
macro_rules! sym_key_com_self {
	($st:ty,$core:ty) => {
		impl $crate::cryptomat::SymKeyComposerWrapper for $st
		{
			type SymmetricKeyWrapper = Self;
			type Composer = $core;

			fn from_inner(
				inner: <<Self as $crate::cryptomat::SymKeyComposerWrapper>::Composer as sentc_crypto_core::cryptomat::SymKeyComposer>::SymmetricKey,
				id: String,
			) -> Self::SymmetricKeyWrapper
			{
				Self {
					key_id: id,
					key: inner,
				}
			}
		}
	};
}

//__________________________________________________________________________________________________

#[macro_export]
macro_rules! static_key_pair_self {
	($sk:ty,$core_sk:ty, $pk:ident, $pk_to_str:ident) => {
		impl $crate::cryptomat::StaticKeyPairWrapper for $sk
		{
			type PkWrapper = $pk;
			type KeyGen = $core_sk;

			fn pk_from_inner(
				inner: <<Self as $crate::cryptomat::StaticKeyPairWrapper>::KeyGen as sentc_crypto_core::cryptomat::StaticKeyPair>::PublicKey,
				id: String,
			) -> Self::PkWrapper
			{
				$pk {
					key: inner,
					key_id: id,
				}
			}

			fn pk_inner_to_pem(
				inner: &<<Self as $crate::cryptomat::StaticKeyPairWrapper>::KeyGen as sentc_crypto_core::cryptomat::StaticKeyPair>::PublicKey,
			) -> Result<String, $crate::error::SdkUtilError>
			{
				$pk_to_str(inner)
			}
		}
	};
}

#[macro_export]
macro_rules! static_key_composer_self {
	($sk:ty, $core_sk:ty,$pk:ident,$core_pk:ty,$core_pk_from_str:ident) => {
		impl $crate::cryptomat::StaticKeyComposerWrapper for $sk
		{
			type SkWrapper = Self;
			type PkWrapper = $pk;
			type InnerPk = $core_pk;
			type Composer = $core_sk;

			fn sk_from_inner(
				inner: <<Self as $crate::cryptomat::StaticKeyComposerWrapper>::Composer as sentc_crypto_core::cryptomat::SkComposer>::SecretKey,
				id: String,
			) -> Self::SkWrapper
			{
				Self {
					key_id: id,
					key: inner,
				}
			}

			fn pk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::PkWrapper, $crate::error::SdkUtilError>
			{
				let key = $core_pk_from_str(public_key, alg)?;

				Ok($pk {
					key,
					key_id: id,
				})
			}

			fn pk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerPk, $crate::error::SdkUtilError>
			{
				$core_pk_from_str(public_key, alg)
			}
		}
	};
}

//__________________________________________________________________________________________________

#[macro_export]
macro_rules! sign_key_pair_self {
	($st:ty,$core_sk:ty,$export_core_vk:ident,$export_sig:ident) => {
		impl $crate::cryptomat::SignKeyPairWrapper for $st
		{
			type KeyGen = $core_sk;

			fn vk_inner_to_pem(
				inner: &<<Self as $crate::cryptomat::SignKeyPairWrapper>::KeyGen as sentc_crypto_core::cryptomat::SignKeyPair>::VerifyKey,
			) -> Result<String, $crate::error::SdkUtilError>
			{
				$export_core_vk(inner)
			}

			fn sig_to_string(
				sig: <<<Self as $crate::cryptomat::SignKeyPairWrapper>::KeyGen as sentc_crypto_core::cryptomat::SignKeyPair>::SignKey as SignK>::Signature,
			) -> String
			{
				$export_sig(&sig)
			}
		}
	};
}

#[macro_export]
macro_rules! sign_key_composer_self {
	($st:ty,$core_sk:ty,$vk:ident,$core_vk:ty,$core_vk_from_str:ident,$sig_from_str:ident) => {
		impl $crate::cryptomat::SignComposerWrapper for $st
		{
			type SignKWrapper = Self;
			type VerifyKWrapper = $vk;
			type InnerVk = $core_vk;
			type Composer = $core_sk;

			fn sk_from_inner(
				inner: <<Self as $crate::cryptomat::SignComposerWrapper>::Composer as sentc_crypto_core::cryptomat::SignKeyComposer>::Key,
				id: String,
			) -> Self::SignKWrapper
			{
				Self {
					key_id: id,
					key: inner,
				}
			}

			fn vk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::VerifyKWrapper, $crate::error::SdkUtilError>
			{
				let key = $core_vk_from_str(public_key, alg)?;

				Ok($vk {
					key,
					key_id: id,
				})
			}

			fn vk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerVk, $crate::error::SdkUtilError>
			{
				$core_vk_from_str(public_key, alg)
			}

			fn sig_from_string(
				sig: &str,
				alg: &str,
			) -> Result<
				<<Self as $crate::cryptomat::SignComposerWrapper>::InnerVk as sentc_crypto_core::cryptomat::VerifyK>::Signature,
				$crate::error::SdkUtilError,
			>
			{
				$sig_from_str(sig, alg)
			}
		}
	};
}

//__________________________________________________________________________________________________

#[macro_export]
macro_rules! search_key_composer {
	($st:ty,$core:ty) => {
		impl $crate::cryptomat::SearchableKeyComposerWrapper for $st
		{
			type SearchableKeyWrapper = Self;
			type Composer = $core;

			fn from_inner(
				inner: <<Self as $crate::cryptomat::SearchableKeyComposerWrapper>::Composer as sentc_crypto_core::cryptomat::SearchableKeyComposer>::Key,
				id: String,
			) -> Self::SearchableKeyWrapper
			{
				Self {
					key: inner,
					key_id: id,
				}
			}
		}
	};
}

#[macro_export]
macro_rules! sortable_composer {
	($st:ty,$core:ty) => {
		impl $crate::cryptomat::SortableKeyComposerWrapper for $st
		{
			type SortableKeyWrapper = Self;
			type Composer = $core;

			fn from_inner(
				inner: <<Self as $crate::cryptomat::SortableKeyComposerWrapper>::Composer as sentc_crypto_core::cryptomat::SortableKeyComposer>::Key,
				id: String,
			) -> Self::SortableKeyWrapper
			{
				Self {
					key: inner,
					key_id: id,
				}
			}
		}
	};
}
