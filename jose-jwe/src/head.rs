use alloc::{boxed::Box, string::String, vec::Vec};

use jose_b64::base64ct::Base64;
use jose_b64::serde::{Bytes, Json, Secret};
use jose_jwa::{CekEncryption, Encrypting};
use jose_jwk::{Jwk, Thumbprint};
use serde::{Deserialize, Serialize};

/// JWE headers
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// BASE64URL(UTF8(JWE Protected Header))
    ///
    /// JSON object that contains the Header Parameters that are integrity
    /// protected by the authenticated encryption operation.  These
    /// parameters apply to all recipients of the JWE.  For the JWE
    /// Compact Serialization, this comprises the entire JOSE Header.  For
    /// the JWE JSON Serialization, this is one component of the JOSE
    /// Header.
    pub protected: Json<Protected>,
    /// unprotected headers
    #[serde(flatten)]
    pub unprotected: Unprotected,
}

/// JWE Protected Header
///
/// JSON object that contains the Header Parameters that are integrity
/// protected by the authenticated encryption operation.  These
/// parameters apply to all recipients of the JWE.  For the JWE
/// Compact Serialization, this comprises the entire JOSE Header.  For
/// the JWE JSON Serialization, this is one component of the JOSE
/// Header.
#[derive(Debug, Serialize, Deserialize)]
pub struct Protected {
    /// (Algorithm) Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "alg" Header Parameter defined in Section 4.1.1 of [JWS], except
    /// that the Header Parameter identifies the cryptographic algorithm used
    /// to encrypt or determine the value of the CEK.  The encrypted content
    /// is not usable if the "alg" value does not represent a supported
    /// algorithm, or if the recipient does not have a key that can be used
    /// with that algorithm.
    ///
    /// A list of defined "alg" values for this use can be found in the IANA
    /// "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA]; the initial contents of this registry are the values
    /// defined in Section 4.1 of [JWA].
    ///
    /// RFC 7516 Section 4.1.1
    alg: CekEncryption,

    /// The "enc" (encryption algorithm) Header Parameter identifies the
    /// content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication
    /// Tag.  This algorithm MUST be an AEAD algorithm with a specified key
    /// length.  The encrypted content is not usable if the "enc" value does
    /// not represent a supported algorithm.  "enc" values should either be
    /// registered in the IANA "JSON Web Signature and Encryption Algorithms"
    /// registry established by [JWA] or be a value that contains a
    /// Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
    /// string containing a StringOrURI value.  This Header Parameter MUST be
    /// present and MUST be understood and processed by implementations.
    ///
    /// A list of defined "enc" values for this use can be found in the IANA
    /// "JSON Web Signature and Encryption Algorithms" registry established
    /// by [JWA]; the initial contents of this registry are the values
    /// defined in Section 5.1 of [JWA].
    ///
    /// RFC 7516 Section 4.1.2
    enc: Encrypting,

    /// Compression Algorithm Header Parameter
    ///
    /// The "zip" (compression algorithm) applied to the plaintext before
    /// encryption, if any.  The "zip" value defined by this specification
    /// is:
    ///
    /// o  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
    ///
    /// Other values MAY be used.  Compression algorithm values can be
    /// registered in the IANA "JSON Web Encryption Compression Algorithms"
    /// registry established by [JWA].  The "zip" value is a case-sensitive
    /// string.  If no "zip" parameter is present, no compression is applied
    /// to the plaintext before encryption.  When used, this Header Parameter
    /// MUST be integrity protected; therefore, it MUST occur only within the
    /// JWE Protected Header.  Use of this Header Parameter is OPTIONAL.
    /// This Header Parameter MUST be understood and processed by
    /// implementations.
    ///
    /// RFC 7516 Section 4.1.3
    zip: Option<String>,

    /// JWK Set URL Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "jku" Header Parameter defined in Section 4.1.2 of [JWS], except
    /// that the JWK Set resource contains the public key to which the JWE
    /// was encrypted; this can be used to determine the private key needed
    /// to decrypt the JWE.
    ///
    /// RFC 7516 Section 4.1.4
    jku: (),

    /// JSON Web Key Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "jwk" Header Parameter defined in Section 4.1.3 of [JWS], except
    /// that the key is the public key to which the JWE was encrypted; this
    /// can be used to determine the private key needed to decrypt the JWE.
    ///
    /// RFC 7516 Section 4.1.5
    #[serde(skip_serializing_if = "Option::is_none", default)]
    jwk: Option<Jwk>,

    /// Key ID Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "kid" Header Parameter defined in Section 4.1.4 of [JWS], except
    /// that the key hint references the public key to which the JWE was
    /// encrypted; this can be used to determine the private key needed to
    /// decrypt the JWE.  This parameter allows originators to explicitly
    /// signal a change of key to JWE recipients.
    ///
    /// RFC 7516 Section 4.1.6
    kid: (),

    /// X.509 URL Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "x5u" Header Parameter defined in Section 4.1.5 of [JWS], except
    /// that the X.509 public key certificate or certificate chain [RFC5280]
    /// contains the public key to which the JWE was encrypted; this can be
    /// used to determine the private key needed to decrypt the JWE.
    ///
    /// RFC 7516 Section 4.1.7
    x5u: (),

    /// X.509 Certificate Chain Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "x5c" Header Parameter defined in Section 4.1.6 of [JWS], except
    /// that the X.509 public key certificate or certificate chain [RFC5280]
    /// contains the public key to which the JWE was encrypted; this can be
    /// used to determine the private key needed to decrypt the JWE.
    ///
    /// See Appendix B of [JWS] for an example "x5c" value.
    ///
    /// RFC 7516 Section 4.1.8
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// RFC 7515 Section 4.1.9-10
    #[serde(flatten)]
    pub x5t: Thumbprint,

    /// Type Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "typ" Header Parameter defined in Section 4.1.9 of [JWS], except
    /// that the type is that of this complete JWE.
    ///
    /// RFC 7516 Section 4.1.11
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,

    /// Content Type Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "cty" Header Parameter defined in Section 4.1.10 of [JWS], except
    /// that the type is that of the secured content (the plaintext).
    ///
    /// RFC 7516 Section 4.1.12
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cty: Option<String>,

    /// Critical Header Parameter
    ///
    /// This parameter has the same meaning, syntax, and processing rules as
    /// the "crit" Header Parameter defined in Section 4.1.11 of [JWS],
    /// except that Header Parameters for a JWE are being referred to, rather
    /// than Header Parameters for a JWS.
    ///
    /// RFC 7516 Section 4.1.13
    pub crit: (),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Unprotected {
    /// JWE Shared Unprotected Header
    #[serde(rename = "unprotected")]
    pub shared: SharedUnprotected,
    /// JWE Per-Recipient Unprotected Header
    #[serde(rename = "header")]
    pub per_recipient: PerRecipientUnprotected,
}

/// # JWE Shared Unprotected Header
///
/// JSON object that contains the Header Parameters that apply to all
/// recipients of the JWE that are not integrity protected.  This can
/// only be present when using the JWE JSON Serialization.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharedUnprotected {}

/// # JWE Shared Unprotected Header
///
/// JSON object that contains Header Parameters that apply to a single
/// recipient of the JWE.  These Header Parameter values are not
/// integrity protected.  This can only be present when using the JWE
/// JSON Serialization.
#[derive(Debug, Serialize, Deserialize)]
pub struct PerRecipientUnprotected {}
