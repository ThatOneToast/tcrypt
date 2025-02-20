//! Key exchange module implementing Diffie-Hellman using X25519
//!
//! This module provides the basic building blocks for performing
//! secure key exchanges between parties.

use aes_gcm::aead::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// 
pub mod protocol;

/// Implements Diffie-Hellman key exchange using X25519
#[derive(Clone)]
pub struct DHKeyExchange {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl DHKeyExchange {
    /// Creates a new key exchange instance with randomly generated keys
    ///
    /// # Examples
    ///
    /// ```
    /// use tcrypt::key_exchange::DHKeyExchange;
    ///
    /// let exchange = DHKeyExchange::new();
    /// ```
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    /// Generates shared secret using peer's public key
    pub fn generate_shared_secret(&self, peer_public: &PublicKey) -> Vec<u8> {
        let shared_secret = self.private_key.diffie_hellman(peer_public);
        shared_secret.as_bytes().to_vec()
    }

    /// Returns this instance's public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}
