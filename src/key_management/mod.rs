//! Key management module providing high-level key exchange protocols
//!
//! This module implements the key management infrastructure, including
//! key generation, exchange protocols, and error handling.

use aes_gcm::aead::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

///
pub mod wrappers;

#[derive(Debug, thiserror::Error)]
/// Errors that can occur during key exchange operations
pub enum KeyExchangeError {
    /// Key exchange process has not been completed
    #[error("Key exchange not completed")]
    IncompleteExchange,

    /// The provided public key is invalid or corrupted
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Failed to generate or compute shared secret
    #[error("Failed to generate shared secret")]
    SharedSecretError,
}
/// Manages the key exchange process and shared secret generation
///
/// # Examples
///
/// ```
/// use tcrypt::key_management::KeyExchange;
///
/// let mut exchange = KeyExchange::new();
/// let public_key = exchange.public_key();
/// ```
#[derive(Clone)]
pub struct KeyExchange {
    private_key: StaticSecret,
    public_key: PublicKey,
    shared_secret: Option<Vec<u8>>,
}

impl KeyExchange {
    /// Creates a new key exchange instance with fresh key pair
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
            shared_secret: None,
        }
    }

    /// Returns this instance's public key for sharing with peers
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Computes shared secret using peer's public key
    pub fn compute_shared_secret(
        &mut self,
        peer_public: &PublicKey,
    ) -> Result<Vec<u8>, KeyExchangeError> {
        let shared_secret = self.private_key.diffie_hellman(peer_public);
        // Hash the shared secret for better key distribution
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let derived_key = hasher.finalize().to_vec();

        self.shared_secret = Some(derived_key.clone());
        Ok(derived_key)
    }

    /// Returns the computed shared secret if available
    pub fn get_shared_secret(&self) -> Result<&[u8], KeyExchangeError> {
        self.shared_secret
            .as_deref()
            .ok_or(KeyExchangeError::IncompleteExchange)
    }
}
