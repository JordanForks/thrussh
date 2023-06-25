// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::encoding::{Encoding, Reader};
pub use crate::signature::*;
use crate::Error;
use cryptovec::CryptoVec;
#[cfg(feature = "openssl")]
use openssl::pkey::{Private, Public};
#[cfg(feature = "p256")]
use p256::ecdsa::signature::Verifier;
use thrussh_libsodium as sodium;

/// Keys for elliptic curve Ed25519 cryptography.
pub mod ed25519 {
    pub use thrussh_libsodium::ed25519::{
        keypair, sign_detached, verify_detached, PublicKey, SecretKey,
    };
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
/// Name of a public key algorithm.
pub struct Name(pub &'static str);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The name of the Ed25519 algorithm for SSH.
pub const ED25519: Name = Name("ssh-ed25519");
/// The name of the ssh-sha2-512 algorithm for SSH.
pub const RSA_SHA2_512: Name = Name("rsa-sha2-512");
/// The name of the ssh-sha2-256 algorithm for SSH.
pub const RSA_SHA2_256: Name = Name("rsa-sha2-256");
/// The name of the ecdsa-sha2-nistp256 algorithm for SSH.
pub const ECDSA_SHA2_NISTP256: Name = Name("ecdsa-sha2-nistp256");

pub const SSH_RSA: Name = Name("ssh-rsa");

impl Name {
    /// Base name of the private key file for a key name.
    pub fn identity_file(&self) -> &'static str {
        match *self {
            ED25519 => "id_ed25519",
            RSA_SHA2_512 => "id_rsa",
            RSA_SHA2_256 => "id_rsa",
            _ => unreachable!(),
        }
    }
}

#[doc(hidden)]
pub trait Verify {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool;
}

/// The hash function used for hashing buffers.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    /// SHA2, 256 bits.
    SHA2_256,
    /// SHA2, 512 bits.
    SHA2_512,
    /// SHA1
    SHA1,
}

impl SignatureHash {
    pub fn name(&self) -> Name {
        match *self {
            SignatureHash::SHA2_256 => RSA_SHA2_256,
            SignatureHash::SHA2_512 => RSA_SHA2_512,
            SignatureHash::SHA1 => SSH_RSA,
        }
    }

    #[cfg(feature = "openssl")]
    fn to_message_digest(&self) -> openssl::hash::MessageDigest {
        use openssl::hash::MessageDigest;
        match *self {
            SignatureHash::SHA2_256 => MessageDigest::sha256(),
            SignatureHash::SHA2_512 => MessageDigest::sha512(),
            SignatureHash::SHA1 => MessageDigest::sha1(),
        }
    }
}

/// Public key
#[derive(Eq, PartialEq, Debug)]
pub enum PublicKey {
    #[doc(hidden)]
    Ed25519(thrussh_libsodium::ed25519::PublicKey),
    #[doc(hidden)]
    #[cfg(feature = "openssl")]
    RSA {
        key: OpenSSLPKey,
        hash: SignatureHash,
    },
    #[doc(hidden)]
    #[cfg(feature = "p256")]
    P256(p256::PublicKey),
}

/// A public key from OpenSSL.
#[cfg(feature = "openssl")]
pub struct OpenSSLPKey(pub openssl::pkey::PKey<Public>);

#[cfg(feature = "openssl")]
use std::cmp::{Eq, PartialEq};
#[cfg(feature = "openssl")]
impl PartialEq for OpenSSLPKey {
    fn eq(&self, b: &OpenSSLPKey) -> bool {
        self.0.public_eq(&b.0)
    }
}
#[cfg(feature = "openssl")]
impl Eq for OpenSSLPKey {}
#[cfg(feature = "openssl")]
impl std::fmt::Debug for OpenSSLPKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OpenSSLPKey {{ (hidden) }}")
    }
}

impl PublicKey {
    /// Parse a public key in SSH format.
    pub fn parse(algo: &[u8], pubkey: &[u8]) -> Result<Self, Error> {
        match algo {
            b"ssh-ed25519" => {
                let mut p = pubkey.reader(0);
                let key_algo = p.read_string()?;
                let key_bytes = p.read_string()?;
                if key_algo != b"ssh-ed25519" || key_bytes.len() != sodium::ed25519::PUBLICKEY_BYTES
                {
                    return Err(Error::CouldNotReadKey.into());
                }
                let mut p = sodium::ed25519::PublicKey {
                    key: [0; sodium::ed25519::PUBLICKEY_BYTES],
                };
                p.key.clone_from_slice(key_bytes);
                Ok(PublicKey::Ed25519(p))
            }
            b"ssh-rsa" | b"rsa-sha2-256" | b"rsa-sha2-512" if cfg!(feature = "openssl") => {
                #[cfg(feature = "openssl")]
                {
                    let mut p = pubkey.reader(0);
                    let key_algo = p.read_string()?;
                    debug!("{:?}", std::str::from_utf8(key_algo));
                    if key_algo != b"ssh-rsa"
                        && key_algo != b"rsa-sha2-256"
                        && key_algo != b"rsa-sha2-512"
                    {
                        return Err(Error::CouldNotReadKey.into());
                    }
                    let key_e = p.read_string()?;
                    let key_n = p.read_string()?;
                    use openssl::bn::BigNum;
                    use openssl::pkey::PKey;
                    use openssl::rsa::Rsa;
                    Ok(PublicKey::RSA {
                        key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                            BigNum::from_slice(key_n)?,
                            BigNum::from_slice(key_e)?,
                        )?)?),
                        hash: {
                            if algo == b"rsa-sha2-256" {
                                SignatureHash::SHA2_256
                            } else if algo == b"rsa-sha2-512" {
                                SignatureHash::SHA2_512
                            } else {
                                SignatureHash::SHA1
                            }
                        },
                    })
                }
                #[cfg(not(feature = "openssl"))]
                {
                    unreachable!()
                }
            }
            b"ecdsa-sha2-nistp256" if cfg!(feature = "p256") => {
                #[cfg(feature = "p256")]
                {
                    let mut p = pubkey.reader(0);
                    let key_algo = p.read_string()?;
                    let identifier = p.read_string()?;
                    if key_algo != b"ecdsa-sha2-nistp256" || identifier != b"nistp256" {
                        debug!("Rejecting {identifier:?} for not being nistp256");
                        return Err(Error::CouldNotReadKey.into());
                    }
                    let sec1_bytes = p.read_string()?;
                    return p256::PublicKey::from_sec1_bytes(sec1_bytes)
                        .map(PublicKey::P256)
                        .map_err(|e| {
                            debug!("from_sec1_bytes failure: {e:?}");
                            Error::CouldNotReadKey
                        });
                }
                #[cfg(not(feature = "p256"))]
                unreachable!();
            }
            _ => Err(Error::CouldNotReadKey.into()),
        }
    }

    /// Algorithm name for that key.
    pub fn name(&self) -> &'static str {
        match *self {
            PublicKey::Ed25519(_) => ED25519.0,
            #[cfg(feature = "openssl")]
            PublicKey::RSA { ref hash, .. } => hash.name().0,
            #[cfg(feature = "p256")]
            PublicKey::P256(_) => ECDSA_SHA2_NISTP256.0,
        }
    }

    /// Verify a signature.
    pub fn verify_detached(&self, buffer: &[u8], sig: &[u8]) -> bool {
        match self {
            &PublicKey::Ed25519(ref public) => {
                sodium::ed25519::verify_detached(&sig, buffer, &public)
            }
            #[cfg(feature = "openssl")]
            &PublicKey::RSA { ref key, ref hash } => {
                use openssl::sign::*;
                let verify = || {
                    let mut verifier = Verifier::new(hash.to_message_digest(), &key.0)?;
                    verifier.update(buffer)?;
                    verifier.verify(&sig)
                };
                verify().unwrap_or(false)
            }
            #[cfg(feature = "p256")]
            &PublicKey::P256(ref public) => {
                let mut reader = sig.reader(0);
                let mut concat = [0u8; 64];
                // Ad-hoc reading of mpints:
                //  - We only consider the last 32 bytes => leading 0 is still treated fine
                //  - We implicitly pad missing leading bytes as 0, which is also fine for a modular value
                match reader.read_mpint() {
                    Ok(r) => r.into_iter().rev().enumerate().for_each(|(i, b)| {
                        if i < 32 {
                            concat[31 - i] = *b;
                        }
                    }),
                    Err(_) => {
                        debug!("Malformed scalar: r");
                        return false;
                    }
                };
                match reader.read_mpint() {
                    Ok(s) => s.into_iter().rev().enumerate().for_each(|(i, b)| {
                        if i < 32 {
                            concat[63 - i] = *b;
                        }
                    }),
                    Err(_) => {
                        debug!("Malformed scalar: s");
                        return false;
                    }
                };

                p256::ecdsa::Signature::from_slice(&concat)
                    .and_then(|sig| {
                        p256::ecdsa::VerifyingKey::from(public)
                            .verify(buffer, &sig)
                            .map(|()| true)
                    })
                    .unwrap_or(false)
            }
        }
    }

    /// Compute the key fingerprint, hashed with sha2-256.
    pub fn fingerprint(&self) -> String {
        use super::PublicKeyBase64;
        let key = self.public_key_bytes();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key[..]);
        data_encoding::BASE64_NOPAD.encode(&hasher.finalize())
    }

    #[cfg(feature = "openssl")]
    pub fn set_algorithm(&mut self, algorithm: &[u8]) {
        if let PublicKey::RSA { ref mut hash, .. } = self {
            if algorithm == b"rsa-sha2-512" {
                *hash = SignatureHash::SHA2_512
            } else if algorithm == b"rsa-sha2-256" {
                *hash = SignatureHash::SHA2_256
            } else if algorithm == b"ssh-rsa" {
                *hash = SignatureHash::SHA1
            }
        }
    }

    #[cfg(not(feature = "openssl"))]
    pub fn set_algorithm(&mut self, _: &[u8]) {}
}

impl Verify for PublicKey {
    fn verify_client_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
    fn verify_server_auth(&self, buffer: &[u8], sig: &[u8]) -> bool {
        self.verify_detached(buffer, sig)
    }
}

/// Public key exchange algorithms.
pub enum KeyPair {
    Ed25519(sodium::ed25519::SecretKey),
    #[cfg(feature = "openssl")]
    RSA {
        key: openssl::rsa::Rsa<Private>,
        hash: SignatureHash,
    },
    #[cfg(feature = "p256")]
    P256(p256::SecretKey),
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyPair::Ed25519(ref key) => write!(
                f,
                "Ed25519 {{ public: {:?}, secret: (hidden) }}",
                &key.key[32..]
            ),
            #[cfg(feature = "openssl")]
            KeyPair::RSA { .. } => write!(f, "RSA {{ (hidden) }}"),
            #[cfg(feature = "p256")]
            KeyPair::P256(_) => write!(f, "P256( (hidden) )"),
        }
    }
}

impl<'b> crate::encoding::Bytes for &'b KeyPair {
    fn bytes(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

impl KeyPair {
    /// Copy the public key of this algorithm.
    pub fn clone_public_key(&self) -> PublicKey {
        match self {
            &KeyPair::Ed25519(ref key) => {
                let mut public = sodium::ed25519::PublicKey { key: [0; 32] };
                public.key.clone_from_slice(&key.key[32..]);
                PublicKey::Ed25519(public)
            }
            #[cfg(feature = "openssl")]
            &KeyPair::RSA { ref key, ref hash } => {
                use openssl::pkey::PKey;
                use openssl::rsa::Rsa;
                let key = Rsa::from_public_components(
                    key.n().to_owned().unwrap(),
                    key.e().to_owned().unwrap(),
                )
                .unwrap();
                PublicKey::RSA {
                    key: OpenSSLPKey(PKey::from_rsa(key).unwrap()),
                    hash: hash.clone(),
                }
            }
            #[cfg(feature = "p256")]
            &KeyPair::P256(ref key) => PublicKey::P256(key.public_key().to_owned()),
        }
    }

    /// Name of this key algorithm.
    pub fn name(&self) -> &'static str {
        match *self {
            KeyPair::Ed25519(_) => ED25519.0,
            #[cfg(feature = "openssl")]
            KeyPair::RSA { ref hash, .. } => hash.name().0,
            #[cfg(feature = "p256")]
            KeyPair::P256(_) => ECDSA_SHA2_NISTP256.0,
        }
    }

    /// Generate a key pair.
    pub fn generate_ed25519() -> Option<Self> {
        let (public, secret) = sodium::ed25519::keypair();
        assert_eq!(&public.key, &secret.key[32..]);
        Some(KeyPair::Ed25519(secret))
    }

    #[cfg(feature = "openssl")]
    pub fn generate_rsa(bits: usize, hash: SignatureHash) -> Option<Self> {
        let key = openssl::rsa::Rsa::generate(bits as u32).ok()?;
        Some(KeyPair::RSA { key, hash })
    }

    #[cfg(feature = "p256")]
    pub fn generate_p256() -> Option<Self> {
        Some(KeyPair::P256(p256::SecretKey::random(
            &mut rand::rngs::OsRng::default(),
        )))
    }

    /// Sign a slice using this algorithm.
    pub fn sign_detached(&self, to_sign: &[u8]) -> Result<Signature, Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => Ok(Signature::Ed25519(SignatureBytes(
                sodium::ed25519::sign_detached(to_sign.as_ref(), secret).0,
            ))),

            #[cfg(feature = "openssl")]
            &KeyPair::RSA { ref key, ref hash } => Ok(Signature::RSA {
                bytes: rsa_signature(hash, key, to_sign.as_ref())?,
                hash: *hash,
            }),

            #[cfg(feature = "p256")]
            &KeyPair::P256(ref secret) => {
                let sig = p256::ecdsa::SigningKey::from(secret)
                    .sign_recoverable(to_sign)?
                    .0;

                let mut bytes = vec![];
                bytes.extend_ssh_mpint(&sig.r().as_ref().to_bytes());
                bytes.extend_ssh_mpint(&sig.s().as_ref().to_bytes());
                Ok(Signature::P256(bytes))
            }
        }
    }

    #[doc(hidden)]
    /// This is used by the server to sign the initial DH kex
    /// message. Note: we are not signing the same kind of thing as in
    /// the function below, `add_self_signature`.
    pub fn add_signature<H: AsRef<[u8]>>(
        &self,
        buffer: &mut CryptoVec,
        to_sign: H,
    ) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = sodium::ed25519::sign_detached(to_sign.as_ref(), secret);

                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            #[cfg(feature = "openssl")]
            &KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, to_sign.as_ref())?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            #[cfg(feature = "p256")]
            &KeyPair::P256(ref secret) => {
                let sig = p256::ecdsa::SigningKey::from(secret)
                    .sign_recoverable(to_sign.as_ref())?
                    .0
                    .to_bytes();
                buffer.push_u32_be((ECDSA_SHA2_NISTP256.0.len() + sig.len() + 8) as u32);
                buffer.extend_ssh_string(ECDSA_SHA2_NISTP256.0.as_bytes());
                buffer.extend_ssh_string(&sig);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    /// This is used by the client for authentication. Note: we are
    /// not signing the same kind of thing as in the above function,
    /// `add_signature`.
    pub fn add_self_signature(&self, buffer: &mut CryptoVec) -> Result<(), Error> {
        match self {
            &KeyPair::Ed25519(ref secret) => {
                let signature = sodium::ed25519::sign_detached(&buffer, secret);
                buffer.push_u32_be((ED25519.0.len() + signature.0.len() + 8) as u32);
                buffer.extend_ssh_string(ED25519.0.as_bytes());
                buffer.extend_ssh_string(&signature.0);
            }
            #[cfg(feature = "openssl")]
            &KeyPair::RSA { ref key, ref hash } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let signature = rsa_signature(hash, key, buffer)?;
                let name = hash.name();
                buffer.push_u32_be((name.0.len() + signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&signature);
            }
            #[cfg(feature = "p256")]
            &KeyPair::P256(ref secret) => {
                let sig = p256::ecdsa::SigningKey::from(secret)
                    .sign_recoverable(&buffer)?
                    .0
                    .to_bytes();
                buffer.push_u32_be((ECDSA_SHA2_NISTP256.0.len() + sig.len() + 8) as u32);
                buffer.extend_ssh_string(ECDSA_SHA2_NISTP256.0.as_bytes());
                buffer.extend_ssh_string(&sig);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "openssl")]
fn rsa_signature(
    hash: &SignatureHash,
    key: &openssl::rsa::Rsa<Private>,
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    use openssl::pkey::*;
    use openssl::rsa::*;
    use openssl::sign::Signer;
    let pkey = PKey::from_rsa(Rsa::from_private_components(
        key.n().to_owned()?,
        key.e().to_owned()?,
        key.d().to_owned()?,
        key.p().unwrap().to_owned()?,
        key.q().unwrap().to_owned()?,
        key.dmp1().unwrap().to_owned()?,
        key.dmq1().unwrap().to_owned()?,
        key.iqmp().unwrap().to_owned()?,
    )?)?;
    let mut signer = Signer::new(hash.to_message_digest(), &pkey)?;
    signer.update(b)?;
    Ok(signer.sign_to_vec()?)
}

/// Parse a public key from a byte slice.
pub fn parse_public_key(p: &[u8]) -> Result<PublicKey, Error> {
    let mut pos = p.reader(0);
    let t = pos.read_string()?;
    if t == b"ssh-ed25519" {
        if let Ok(pubkey) = pos.read_string() {
            use thrussh_libsodium::ed25519;
            let mut p = ed25519::PublicKey {
                key: [0; ed25519::PUBLICKEY_BYTES],
            };
            p.key.clone_from_slice(pubkey);
            return Ok(PublicKey::Ed25519(p));
        }
    }
    if t == b"ssh-rsa" {
        #[cfg(feature = "openssl")]
        {
            let e = pos.read_string()?;
            let n = pos.read_string()?;
            use openssl::bn::*;
            use openssl::pkey::*;
            use openssl::rsa::*;
            return Ok(PublicKey::RSA {
                key: OpenSSLPKey(PKey::from_rsa(Rsa::from_public_components(
                    BigNum::from_slice(n)?,
                    BigNum::from_slice(e)?,
                )?)?),
                hash: SignatureHash::SHA2_256,
            });
        }
    }
    if t == b"ecdsa-sha2-nistp256" {
        #[cfg(feature = "p256")]
        {
            if pos.read_string()? != b"nistp256" {
                return Err(Error::CouldNotReadKey);
            }
            let sec1_bytes = pos.read_string()?;
            return p256::PublicKey::from_sec1_bytes(sec1_bytes)
                .map(PublicKey::P256)
                .map_err(|_| Error::CouldNotReadKey);
        }
    }
    Err(Error::CouldNotReadKey.into())
}
