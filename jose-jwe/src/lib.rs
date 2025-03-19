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

pub mod head;

use serde::{Deserialize, Serialize};

use jose_b64::serde::{Bytes, Secret};

pub use head::{Header, PerRecipientUnprotected, Protected, SharedUnprotected, Unprotected};

/// JWT represented as a JWE
#[derive(Debug, Serialize, Deserialize)]
pub struct JWE<AAD> {
    #[serde(flatten)]
    pub header: Header,
    /// BASE64URL(JWE Encrypted Key)
    ///
    /// Encrypted Content Encryption Key value.  Note that for some
    /// algorithms, the JWE Encrypted Key value is specified as being the
    /// empty octet sequence.
    ///
    /// Content Encryption Key (CEK) usually random generated value,
    /// encrypted with the recipient's public key.
    pub encrypted_key: Secret,
    /// BASE64URL(JWE Initialization Vector)
    ///
    /// Initialization Vector value used when encrypting the plaintext.
    /// Note that some algorithms may not use an Initialization Vector, in
    /// which case this value is the empty octet sequence.
    ///
    /// Usually a random generated value.
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<Secret>,
    /// BASE64URL(JWE Ciphertext)
    ///
    /// Ciphertext value resulting from authenticated encryption of the
    /// plaintext with Additional Authenticated Data.
    ///
    /// Encrypt using the CEK as the encryption key, the JWE Initialization Vector,
    /// and the Additional Authenticated Data value.
    pub ciphertext: Secret,
    /// BASE64URL(JWE Authentication Tag)
    ///
    /// Authentication Tag value resulting from authenticated encryption
    /// of the plaintext with Additional Authenticated Data.
    ///
    /// Generated when Authenticated encryption is performed on the plaintext.
    #[serde(rename = "tag")]
    pub authentication_tag: Bytes,
    /// BASE64URL(JWE AAD)
    ///
    /// Additional value to be integrity protected by the authenticated
    /// encryption operation.  This can only be present when using the JWE
    /// JSON Serialization.  (Note that this can also be achieved when
    /// using either the JWE Compact Serialization or the JWE JSON
    /// Serialization by including the AAD value as an integrity-protected
    /// Header Parameter value, but at the cost of the value being double
    /// base64url encoded.)
    pub aad: AAD,
}

/// A JSON Web Signature representation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[serde(untagged)]
pub enum JWE {
    /// General Serialization. This is
    General(General),

    /// Flattened Serialization
    Flattened(Flattened),
}

impl From<General> for Jws {
    fn from(value: General) -> Self {
        Jws::General(value)
    }
}

impl From<Flattened> for Jws {
    fn from(value: Flattened) -> Self {
        Jws::Flattened(value)
    }
}

/// General Serialization
///
/// This is the usual JWS form, which allows multiple signatures to be
/// specified.
///
/// ```json
/// {
///     "payload":"<payload contents>",
///     "signatures":[
///      {"protected":"<integrity-protected header 1 contents>",
///       "header":<non-integrity-protected header 1 contents>,
///       "signature":"<signature 1 contents>"},
///      ...
///      {"protected":"<integrity-protected header N contents>",
///       "header":<non-integrity-protected header N contents>,
///       "signature":"<signature N contents>"}]
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct General {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signatures over the payload.
    pub signatures: Vec<Signature>,
}

impl From<Flattened> for General {
    fn from(value: Flattened) -> Self {
        Self {
            payload: value.payload,
            signatures: vec![value.signature],
        }
    }
}

/// Flattened Serialization
///
/// This is similar to the general serialization but is more compact, only
/// supporting one signature.
///
/// ```json
/// {
///     "payload":"<payload contents>",
///     "protected":"<integrity-protected header contents>",
///     "header":<non-integrity-protected header contents>,
///     "signature":"<signature contents>"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flattened {
    /// The payload of the signature.
    pub payload: Option<Bytes>,

    /// The signature over the payload.
    #[serde(flatten)]
    pub signature: Signature,
}

/// A Signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    /// The JWS Unprotected Header
    pub header: Option<Unprotected>,

    /// The JWS Protected Header
    pub protected: Option<Json<Protected>>,

    /// The Signature Bytes
    pub signature: Bytes,
}
