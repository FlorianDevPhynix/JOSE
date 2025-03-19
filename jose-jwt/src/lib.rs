#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

mod json;

use alloc::{collections::btree_map::BTreeMap, format, string::String};
use jose_b64::base64ct::Encoding;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::json::Json;

/// Implemnted for Claim structures to verify its contents.
pub trait Verify {
    fn verify(&self) -> Result<(), signature::Error>;
}

pub type JwtHeader = jose_jws::Unprotected;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "C: Serialize + DeserializeOwned")]
pub struct Jwt<C> {
    /// The JWT Header
    pub header: Json<JwtHeader>,

    /// The JWT Claims
    pub claims: Json<C>,

    /// The Signature Bytes
    pub signature: String,
}

impl<C: Serialize> Jwt<C> {
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        use jose_b64::base64ct::Base64UrlUnpadded;

        let header = Base64UrlUnpadded::encode_string(serde_json::to_vec(&self.header)?.as_slice());
        let payload =
            Base64UrlUnpadded::encode_string(serde_json::to_vec(&self.claims)?.as_slice());
        const BUF_SIZE: usize = 128;
        let mut enc_buf = [0u8; BUF_SIZE];

        Ok(format!("{}.{}.{}", header, payload, self.signature))
    }
}

impl<C: Serialize> core::fmt::Display for Jwt<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Error;
        use jose_b64::base64ct::Base64UrlUnpadded;

        let header = Base64UrlUnpadded::encode_string(
            serde_json::to_vec(&self.header)
                .map_err(|_| Error {})?
                .as_slice(),
        );
        let payload = Base64UrlUnpadded::encode_string(
            serde_json::to_vec(&self.claims)
                .map_err(|_| Error {})?
                .as_slice(),
        );

        let signature = Base64UrlUnpadded::encode_string(self.signature.as_bytes());
        write!(f, "{header}.{payload}.{signature}")
    }
}

/// Standardised and often used JWT Headers
#[derive(Clone, Debug, Serialize, Deserialize)]
struct JwtHeaderExt {
    /// JSON Key URL
    ///
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// X.509 URL
    ///
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
}

pub(crate) fn btreemap_empty(map: &BTreeMap<String, Value>) -> bool {
    map.is_empty()
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct JwtClaims<E> {
    /// The issuer of this token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Unique id of the subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// client_id of the oauth2 rp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiry in utc epoch seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not valid before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// If you wish to include extensions as a struct, you can use this struct. If you do
    /// not have extensions, set this type to () with `Jwt<()>` and it will be skipped.
    #[serde(flatten)]
    pub extensions: E,
    /// Arbitrary custom claims that are not part of your extension struct,
    /// will be caught here to not loose any data.
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    claims: BTreeMap<String, Value>,
}

/* impl<E> Verify for JwtClaims<E> {
    fn verify(&self) -> Result<(), signature::Error> {}
} */

/* struct Test<'s> {
    msg: &'s [u8],
}

impl<'s> Test<'s> {
    pub fn test<S, V: signature::Verifier<S>>(&self, verifier: V) -> signature::Error {
        verifier.verify(&self.msg, signature)
    }
} */

pub fn test() {
    let jws: jose_jws::Jws = serde_json::from_slice(b"").unwrap();

    //jws.
}
