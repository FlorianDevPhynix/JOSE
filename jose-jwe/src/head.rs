use serde::{Deserialize, Serialize};

/// JWE headers
#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    /// BASE64URL(UTF8(JWE Protected Header))
    pub protected: Protected,
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
    alg: alloc::string::String,

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
    enc: alloc::string::String,

    /// (Compression Algorithm) Header Parameter
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
    zip: alloc::string::String,
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
