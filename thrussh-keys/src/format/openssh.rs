use crate::encoding::Reader;
use crate::key;
use crate::{Error, KEYTYPE_ED25519, KEYTYPE_P256, KEYTYPE_RSA};
use bcrypt_pbkdf;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<key::KeyPair, Error> {
    if &secret[0..15] == b"openssh-key-v1\0" {
        let mut position = secret.reader(15);

        let ciphername = position.read_string()?;
        let kdfname = position.read_string()?;
        let kdfoptions = position.read_string()?;

        let nkeys = position.read_u32()?;

        // Read all public keys
        for _ in 0..nkeys {
            position.read_string()?;
        }

        // Read all secret keys
        let secret_ = position.read_string()?;
        let secret = decrypt_secret_key(ciphername, kdfname, kdfoptions, password, secret_)?;
        let mut position = secret.reader(0);
        let _check0 = position.read_u32()?;
        let _check1 = position.read_u32()?;
        for _ in 0..nkeys {
            let key_type = position.read_string()?;
            if key_type == KEYTYPE_ED25519 {
                let pubkey = position.read_string()?;
                let seckey = position.read_string()?;
                let _comment = position.read_string()?;
                assert_eq!(pubkey, &seckey[32..]);
                use key::ed25519::*;
                let mut secret = SecretKey::new_zeroed();
                secret.key.clone_from_slice(seckey);
                return Ok(key::KeyPair::Ed25519(secret));
            } else if key_type == KEYTYPE_RSA && cfg!(feature = "openssl") {
                #[cfg(feature = "openssl")]
                {
                    let n = BigNum::from_slice(position.read_string()?)?;
                    let e = BigNum::from_slice(position.read_string()?)?;
                    let d = BigNum::from_slice(position.read_string()?)?;
                    let iqmp = BigNum::from_slice(position.read_string()?)?;
                    let p = BigNum::from_slice(position.read_string()?)?;
                    let q = BigNum::from_slice(position.read_string()?)?;

                    let mut ctx = openssl::bn::BigNumContext::new()?;
                    let un = openssl::bn::BigNum::from_u32(1)?;
                    let mut p1 = openssl::bn::BigNum::new()?;
                    let mut q1 = openssl::bn::BigNum::new()?;
                    p1.checked_sub(&p, &un)?;
                    q1.checked_sub(&q, &un)?;
                    let mut dmp1 = openssl::bn::BigNum::new()?; // d mod p-1
                    dmp1.checked_rem(&d, &p1, &mut ctx)?;
                    let mut dmq1 = openssl::bn::BigNum::new()?; // d mod q-1
                    dmq1.checked_rem(&d, &q1, &mut ctx)?;

                    let key = openssl::rsa::RsaPrivateKeyBuilder::new(n, e, d)?
                        .set_factors(p, q)?
                        .set_crt_params(dmp1, dmq1, iqmp)?
                        .build();
                    key.check_key().unwrap();
                    return Ok(key::KeyPair::RSA {
                        key,
                        hash: key::SignatureHash::SHA2_512,
                    });
                }
            } else if key_type == KEYTYPE_P256 && cfg!(feature = "p256") {
                #[cfg(feature = "p256")]
                {
                    let _nistp256 = position.read_string()?;
                    let pub_bytes = position.read_string()?;
                    let sec_bytes = position.read_mpint()?;
                    let _comment = position.read_string()?;
                    let mut key_bytes = [0u8; 32];
                    // Reading mpints in a naive way, but sufficient for modular values here
                    sec_bytes.into_iter().rev().enumerate().for_each(|(i, b)| {
                        if i < 32 {
                            key_bytes[31 - i] = *b;
                        }
                    });
                    let key = p256::SecretKey::from_bytes(&key_bytes.into())?;
                    if key.public_key().to_sec1_bytes().as_ref() != pub_bytes {
                        return Err(Error::CouldNotReadKey);
                    }
                    return Ok(key::KeyPair::P256(key));
                }
            } else {
                return Err(Error::UnsupportedKeyType(key_type.to_vec()).into());
            }
        }
        Err(Error::CouldNotReadKey.into())
    } else {
        Err(Error::CouldNotReadKey.into())
    }
}

use aes::*;
use block_modes::block_padding::NoPadding;
type Aes128Cbc = block_modes::Cbc<Aes128, NoPadding>;
type Aes256Cbc = block_modes::Cbc<Aes256, NoPadding>;

fn decrypt_secret_key(
    ciphername: &[u8],
    kdfname: &[u8],
    kdfoptions: &[u8],
    password: Option<&str>,
    secret_key: &[u8],
) -> Result<Vec<u8>, Error> {
    if kdfname == b"none" {
        if password.is_none() {
            Ok(secret_key.to_vec())
        } else {
            Err(Error::CouldNotReadKey.into())
        }
    } else if let Some(password) = password {
        let mut key = [0; 48];
        let n = match ciphername {
            b"aes128-cbc" | b"aes128-ctr" => 32,
            b"aes256-cbc" | b"aes256-ctr" => 48,
            _ => return Err(Error::CouldNotReadKey.into()),
        };
        match kdfname {
            b"bcrypt" => {
                let mut kdfopts = kdfoptions.reader(0);
                let salt = kdfopts.read_string()?;
                let rounds = kdfopts.read_u32()?;
                bcrypt_pbkdf::bcrypt_pbkdf(password, salt, rounds, &mut key[..n]).unwrap();
            }
            _kdfname => {
                return Err(Error::CouldNotReadKey.into());
            }
        };
        let (key, iv) = key.split_at(n - 16);

        let mut dec = secret_key.to_vec();
        dec.resize(dec.len() + 32, 0u8);
        use aes::cipher::{NewCipher, StreamCipher};
        use block_modes::BlockMode;
        match ciphername {
            b"aes128-cbc" => {
                let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt(&mut dec)?.len();
                dec.truncate(n)
            }
            b"aes256-cbc" => {
                let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
                let n = cipher.decrypt(&mut dec)?.len();
                dec.truncate(n)
            }
            b"aes128-ctr" => {
                let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut dec);
                dec.truncate(secret_key.len())
            }
            b"aes256-ctr" => {
                let mut cipher = Aes256Ctr::new_from_slices(key, iv).unwrap();
                cipher.apply_keystream(&mut dec);
                dec.truncate(secret_key.len())
            }
            _ => {}
        }
        Ok(dec)
    } else {
        Err(Error::KeyIsEncrypted.into())
    }
}
