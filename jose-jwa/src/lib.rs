// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

use core::fmt;

use serde::{Deserialize, Serialize};

/// Possible types of algorithms that can exist in an "alg" descriptor.
///
/// Currently only signing algorithms are represented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// Algorithms used for digital signatures and MACs
    Signing(Signing),
    Encrypting(Encrypting),
}

impl From<Signing> for Algorithm {
    #[inline(always)]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

/// Algorithms used for signing, as defined in [RFC7518] section 3.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Signing {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    Es512,

    /// HMAC using SHA-256 (Required)
    Hs256,

    /// HMAC using SHA-384 (Optional)
    Hs384,

    /// HMAC using SHA-512 (Optional)
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    Rs512,

    /// No digital signature or MAC performed (Optional)
    ///
    /// This variant is renamed as `Null` to avoid colliding with `Option::None`.
    #[serde(rename = "none")]
    Null,
}

impl fmt::Display for Signing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

/// Algorithms used for encrypting the CEK, as defined in [RFC7518] section 4.1.
///
/// Algorithms used to encrypt the CEK, producing the JWE
/// Encrypted Key, or to use key agreement to agree upon the CEK.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CekEncryption {
    /// RSAES-PKCS1-v1_5 (Recommended-)
    Rsa1_5,

    /// RSAES OAEP using default parameters (Recommended+)
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256 (Optional)
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with default initial value using 128-bit key (Recommended)
    A128Kw,

    /// AES Key Wrap with default initial value using 192-bit key (Optional)
    A192Kw,

    /// AES Key Wrap with default initial value using 256-bit key (Recommended)
    A256Kw,

    /// Direct use of a shared symmetric key as the CEK (Recommended)
    #[serde(rename = "dir")]
    Dir,

    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement
    /// using Concat KDF (Recommended+)
    /// More Header Params: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" (Recommended)
    /// More Header Params: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128KW,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" (Optional)
    /// More Header Params: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192KW,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" (Recommended)
    /// More Header Params: "epk", "apu", "apv"
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256KW,

    /// Key wrapping with AES GCM using 128-bit key (Optional)
    /// More Header Params: "iv", "tag"
    A128Gcmkw,

    /// Key wrapping with AES GCM using 192-bit key (Optional)
    /// More Header Params: "iv", "tag"
    A192Gcmkw,

    /// Key wrapping with AES GCM using 256-bit key (Optional)
    /// More Header Params: "iv", "tag"
    A256Gcmkw,

    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping (Optional)
    /// More Header Params: "p2s", "p2c"
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,

    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping (Optional)
    /// More Header Params: "p2s", "p2c"
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,

    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping (Optional)
    /// More Header Params: "p2s", "p2c"
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

/// Algorithms used for encrypting, as defined in [RFC7518] section 5.1.
///
/// [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Encrypting {
    /// AES_128_CBC_HMAC_SHA_256 using 128-bit CBC keys and HMAC SHA-256,
    /// as defined in Section 5.2.3. (Required)
    #[serde(rename = "A128CBC-HS256")]
    A128CBCHS256,

    /// AES_192_CBC_HMAC_SHA_384 using 192-bit CBC keys and HMAC SHA-384,
    /// as defined in Section 5.2.4. (Optional)
    #[serde(rename = "A192CBC-HS384")]
    A192CBCHS384,

    /// AES_256_CBC_HMAC_SHA_512 using 256-bit CBC keys and HMAC SHA-512,
    /// as defined in Section5.2.5. (Required)
    #[serde(rename = "A256CBC-HS512")]
    A256CBCHS512,

    /// AES GCM using 128-bit key. (Recommended)
    A128GCM,

    /// AES GCM using 192-bit key. (Optional)
    A192GCM,

    /// AES GCM using 256-bit key. (Recommended)
    A256GCM,
}

impl fmt::Display for Encrypting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;
    use std::vec;

    use super::*;

    #[test]
    fn signing_simple_roundtrip() {
        use Signing::*;

        let input = vec![
            EdDsa, Es256, Es256K, Es384, Es512, Hs256, Hs384, Hs512, Ps256, Ps384, Ps512, Rs256,
            Rs384, Rs512, Null,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["EdDSA","ES256","ES256K","ES384","ES512","HS256","HS384","HS512","PS256","PS384","PS512","RS256","RS384","RS512","none"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Signing>>(&ser).expect("deserialization failed"),
            input
        );
    }

    #[test]
    fn encrypting_simple_roundtrip() {
        use Encrypting::*;

        let input = vec![
            A128CBCHS256,
            A192CBCHS384,
            A256CBCHS512,
            A128GCM,
            A192GCM,
            A256GCM,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["A128CBC-HS256","A192CBC-HS384","A256CBC-HS512","A128GCM","A192GCM","A256GCM"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Encrypting>>(&ser).expect("deserialization failed"),
            input
        );
    }
}
