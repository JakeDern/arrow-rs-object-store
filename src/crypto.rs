// TODO
// type DigestImpl = ;

pub(crate) struct Digest {
    inner: DigestImpl,
}

pub(crate) fn digest_sha256(bytes: &[u8]) -> Vec<u8> {
    CryptoProvider::digest_sha256(bytes)
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    let sha_256_hash = digest_sha256(bytes);
    hex_encode(&sha_256_hash)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // String writing is infallible
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub trait Crypto {
    fn digest_sha256(bytes: &[u8]) -> Vec<u8>;
    fn hmac_sha256(secret: &[u8], bytes: &[u8]) -> Vec<u8>;
}

// Type alias to the current crypto provider based on feature flags
// #[cfg(feature = "open-ssl")]
type CryptoProvider = openssl::OpenSslCrypto;

// #[cfg(not(feature = "open-ssl"))]
// type CryptoProvider = ring::RingCrypto;
#[cfg(feature = "open-ssl")]
mod openssl {
    use openssl::hash::MessageDigest;

    use super::Crypto;

    pub struct OpenSslCrypto;

    impl Crypto for OpenSslCrypto {
        fn digest_sha256(bytes: &[u8]) -> Vec<u8> {
            // TODO: Make this function fallible?
            openssl::hash::hash(MessageDigest::sha256(), bytes)
                .unwrap()
                .to_vec()
        }

        fn hmac_sha256(secret: &[u8], bytes: &[u8]) -> Vec<u8> {
            todo!()
        }
    }
}

// #[cfg(not(feature = "open-ssl"))]
mod ring {
    use super::Crypto;
    pub struct RingCrypto;

    impl Crypto for RingCrypto {
        fn digest_sha256(bytes: &[u8]) -> Vec<u8> {
            ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .to_vec()
        }

        fn hmac_sha256(secret: &[u8], bytes: &[u8]) -> Vec<u8> {
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref());
            ring::hmac::sign(&key, bytes.as_ref()).as_ref().to_vec()
        }
    }
}
