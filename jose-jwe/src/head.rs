use alloc::{boxed::Box, string::String, vec::Vec};

use jose_b64::base64ct::Base64;
use jose_b64::serde::{Bytes, Json};
use jose_jwa::{CekEncryption, Encrypting};
use jose_jwk::{Jwk, Thumbprint};
use serde::{Deserialize, Serialize};

/// JWE headers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// BASE64URL(UTF8(JWE Protected Header))
    ///
    /// JSON object that contains the Header Parameters that are integrity
    /// protected by the authenticated encryption operation. These
    /// parameters apply to all recipients of the JWE. For the JWE
    /// Compact Serialization, this comprises the entire JOSE Header. For
    /// the JWE JSON Serialization, this is one component of the JOSE
    /// Header.
    pub protected: Option<Json<Protected>>,

    /// The JWE Unprotected shared Header
    pub unprotected: Option<Unprotected>,
}

/// JWE Protected Header
///
/// JSON object that contains the Header Parameters that are integrity
/// protected by the authenticated encryption operation. These
/// parameters apply to all recipients of the JWE.  For the JWE
/// Compact Serialization, this comprises the entire JOSE Header. For
/// the JWE JSON Serialization, this is one component of the JOSE
/// Header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protected {
    /// RFC 7516 Section 4.1.2
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enc: Option<Encrypting>,

    /// RFC 7516 Section 4.1.3
    zip: Option<String>,

    /// RFC 7516 Section 4.1.13
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crit: Option<Vec<String>>,

    /// Other values that may appear in the protected header.
    #[serde(flatten)]
    pub oth: Unprotected,

    /// Per-Recipient Unprotected may also appear in the protected header.
    #[serde(flatten)]
    pub recipient: PerRecipientUnprotected,
}

/// # JWE Shared Unprotected Header
///
/// JSON object that contains the Header Parameters that apply to all
/// recipients of the JWE that are not integrity protected.  This can
/// only be present when using the JWE JSON Serialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unprotected {
    /// RFC 7516 Section 4.1.4
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg(feature = "url")]
    pub jku: Option<url::Url>,

    /// RFC 7516 Section 4.1.5
    #[serde(skip_serializing_if = "Option::is_none", default)]
    jwk: Option<Jwk>,

    /// RFC 7516 Section 4.1.7
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[cfg(feature = "url")]
    pub x5u: Option<url::Url>,

    /// RFC 7516 Section 4.1.8
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// RFC 7515 Section 4.1.9-10
    #[serde(flatten)]
    pub x5t: Thumbprint,

    /// RFC 7516 Section 4.1.11
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,

    /// RFC 7516 Section 4.1.12
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cty: Option<String>,
}

/// # JWE Shared Unprotected Header
///
/// JSON object that contains Header Parameters that apply to a single
/// recipient of the JWE.  These Header Parameter values are not
/// integrity protected.  This can only be present when using the JWE
/// JSON Serialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerRecipientUnprotected {
    /// RFC 7516 Section 4.1.1
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<CekEncryption>,

    /// RFC 7516 Section 4.1.6
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
}
