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

mod head;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use jose_b64::serde::{Bytes, Json, Secret};

pub use head::*;

/// A JSON Web Encryption representation
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

impl From<General> for JWE {
    fn from(value: General) -> Self {
        JWE::General(value)
    }
}

impl From<Flattened> for JWE {
    fn from(value: Flattened) -> Self {
        JWE::Flattened(value)
    }
}

/// General Serialization
///
/// This is the usual JWE form, which allows multiple recipients to be
/// specified.
///
/// ```json
/// {
///     "protected":"<integrity-protected shared header contents>",
///     "unprotected":<non-integrity-protected shared header contents>,
///     "recipients":[
///         {"header":<per-recipient unprotected header 1 contents>,
///         "encrypted_key":"<encrypted key 1 contents>"},
///         ...
///         {"header":<per-recipient unprotected header N contents>,
///          "encrypted_key":"<encrypted key N contents>"}
///     ],
///     "aad":"<additional authenticated data contents>",
///     "iv":"<initialization vector contents>",
///     "ciphertext":"<ciphertext contents>",
///     "tag":"<authentication tag contents>"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct General {
    /// The encryption of the payload.
    #[serde(flatten)]
    pub encryption: Encryption,

    /// The JWE Recipients
    pub recipients: Vec<Recipient>,
}

impl From<Flattened> for General {
    fn from(value: Flattened) -> Self {
        Self {
            encryption: value.encryption,
            recipients: alloc::vec![value.recipient],
        }
    }
}

/// Flattened Serialization
///
/// This is similar to the general serialization but is more compact, only
/// supporting one recipient.
///
/// ```json
/// {
///     "protected":"<integrity-protected header contents>",
///     "unprotected":<non-integrity-protected header contents>,
///     "header":<more non-integrity-protected header contents>,
///     "encrypted_key":"<encrypted key contents>",
///     "aad":"<additional authenticated data contents>",
///     "iv":"<initialization vector contents>",
///     "ciphertext":"<ciphertext contents>",
///     "tag":"<authentication tag contents>"
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flattened {
    /// The encryption of the payload.
    #[serde(flatten)]
    pub encryption: Encryption,

    /// The recipient of the payload.
    #[serde(flatten)]
    pub recipient: Recipient,
}

/// Data for a Recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Encryption {
    /// The JWE Header
    #[serde(flatten)]
    pub header: Header,

    /// BASE64URL(JWE AAD)
    ///
    /// Additional value to be integrity protected by the authenticated
    /// encryption operation. (Note that this can also be achieved when
    /// using either the JWE Compact Serialization or the JWE JSON
    /// Serialization by including the AAD value as an integrity-protected
    /// Header Parameter value, but at the cost of the value being double
    /// base64url encoded.)
    pub aad: Option<Secret>,

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
    pub authentication_tag: Secret,
}

/// Data for a Recipient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recipient {
    /// The JWE Unprotected Header
    #[serde(flatten)]
    pub header: Option<PerRecipientUnprotected>,

    /// BASE64URL(JWE Encrypted Key)
    ///
    /// Encrypted Content Encryption Key value.  Note that for some
    /// algorithms, the JWE Encrypted Key value is specified as being the
    /// empty octet sequence.
    ///
    /// Content Encryption Key (CEK) usually random generated value,
    /// encrypted with the recipient's public key.
    pub encrypted_key: Secret,
}
