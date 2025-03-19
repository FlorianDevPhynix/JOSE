//#![cfg(feature = "json")]

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::Deref;
use core::str::FromStr;
use jose_b64::serde::Bytes;

use base64ct::{Base64UrlUnpadded, Encoding};
use jose_b64::base64ct;
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serialize};

use jose_b64::stream::Error;

/// A wrapper for nested, base64-encoded JSON
///
/// [`Json`] handles the case where a type (`T`) is serialized to JSON.
/// Note that [`Json`] internally stores both the base64 encoded bytes **and**
/// the doubly-decoded value. While this uses additional memory, it ensures that
/// the original serialization is not lost. This is important in cryptographic
/// contexts where the original serialization may be included in a
/// cryptographic measurement.
///
/// During deserialization, a full double deserialization is performed. This
/// ensures that an instantiated [`Json`] object is always fully parsed. During
/// serialization, only the pre-serialized bytes are used; the type (`T`) is
/// **not** reserialized.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(transparent)]
pub struct Json<T, B = Box<[u8]>, E = Base64UrlUnpadded> {
    val: T,

    #[serde(skip)]
    buf: Bytes<B, E>,
    #[serde(skip)]
    cfg: PhantomData<E>,
}

impl<T, B, E> Deref for Json<T, B, E> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T, B, E> TryFrom<alloc::string::String> for Json<T, B, E>
where
    T: DeserializeOwned,
    B: From<alloc::string::String>,
    E: Encoding,
{
    type Error = Error<serde_json::Error>;

    fn try_from(s: alloc::string::String) -> Result<Self, Self::Error> {
        let decoded = E::decode_vec(s.as_str())?;
        Ok(Self {
            val: serde_json::from_slice(&decoded).map_err(Error::Inner)?,
            buf: Bytes::from_str(&s)?,
            cfg: PhantomData,
        })
    }
}

impl<T, B, E> Json<T, B, E>
where
    B: From<alloc::string::String>,
    T: Serialize,
    E: Encoding,
{
    /// Creates a new instance by serializing the input to JSON
    /// and encoding that as base64.
    ///
    /// The value `T` and its serialized and base64 encoded bytes
    /// are stored in the object.
    pub fn new(value: T) -> Result<Self, serde_json::Error> {
        let serialized = serde_json::to_vec(&value)?;
        Ok(Self {
            buf: E::encode_string(serialized.as_slice()).into(),
            val: value,
            cfg: PhantomData,
        })
    }
}

impl<T, B, E: Encoding> FromStr for Json<T, B, E>
where
    T: DeserializeOwned,
    B: From<alloc::string::String>,
    E: Encoding,
{
    type Err = Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = E::decode_vec(s)?;
        Ok(Self {
            val: serde_json::from_slice(&decoded).map_err(Error::Inner)?,
            buf: s.to_owned().into(),
            cfg: PhantomData,
        })
    }
}

impl<'de, T, B, E> Deserialize<'de> for Json<T, B, E>
where
    T: Serialize + DeserializeOwned,
    B: From<alloc::string::String>,
    E: Encoding,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = T::deserialize(deserializer)?;

        Ok(match Self::new(value) {
            Err(e) => return Err(D::Error::custom(e)),
            Ok(x) => x,
        })
    }
}
