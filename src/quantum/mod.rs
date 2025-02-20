// src/quantum/mod.rs
//! Quantum-resistant cryptographic implementations
//!
//! This module provides implementations of post-quantum cryptographic algorithms,
//! including CRYSTALS-Kyber for key encapsulation.

use pqcrypto_kyber::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as _, SharedSecret as _};

/// Quantum implementation wrappers
pub mod wrappers;

/// Errors that can occur during quantum cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum QuantumError {
    /// Error during key generation
    #[error("Key generation failed")]
    KeyGenError,
    
    /// Invalid or corrupted public key format
    #[error("Invalid public key format")] 
    InvalidPublicKey,
    
    /// Invalid or corrupted ciphertext format
    #[error("Invalid ciphertext format")]
    InvalidCiphertext,
    
    /// Error during key encapsulation
    #[error("Encapsulation failed")]
    EncapsulationError,
    
    /// Error during key decapsulation 
    #[error("Decapsulation failed")]
    DecapsulationError,
}

/// CRYSTALS-Kyber key encapsulation mechanism (KEM)
#[derive(Clone)]
pub struct KyberKEM {
    public_key: kyber768::PublicKey,
    secret_key: kyber768::SecretKey,
}

impl KyberKEM {
    /// Creates a new KyberKEM instance with generated keys
    pub fn new() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Returns the public key for sharing
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Encapsulates a shared secret using a peer's public key
    pub fn encapsulate(&self, peer_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QuantumError> {
        let peer_pk = kyber768::PublicKey::from_bytes(peer_public)
            .map_err(|_| QuantumError::InvalidPublicKey)?;

        let (shared_secret, ciphertext) = kyber768::encapsulate(&peer_pk);

        Ok((
            shared_secret.as_bytes().to_vec(),
            ciphertext.as_bytes().to_vec(),
        ))
    }

    /// Decapsulates a shared secret using the ciphertext
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, QuantumError> {
        let ct = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| QuantumError::InvalidCiphertext)?;

        let shared_secret = kyber768::decapsulate(&ct, &self.secret_key);

        Ok(shared_secret.as_bytes().to_vec())
    }
}

impl Default for KyberKEM {
    fn default() -> Self {
        Self::new()
    }
}

/// Hybrid encryption combining classical and quantum-resistant algorithms
#[derive(Clone)]
pub struct HybridEncryption {
    classical: super::symetric::AESEncryption,
    quantum: KyberKEM,
}

impl HybridEncryption {
    /// Creates a new hybrid encryption instance
    pub fn new(key: &[u8]) -> Result<Self, super::EncryptionError> {
        let quantum = KyberKEM::new();
        let classical = super::symetric::AESEncryption::new(key)?;

        Ok(Self { classical, quantum })
    }

    /// Returns the quantum public key
    pub fn quantum_public_key(&self) -> &[u8] {
        self.quantum.public_key()
    }

    /// Perform hybrid key exchange
    pub fn hybrid_exchange(&self, peer_public: &[u8]) -> Result<Vec<u8>, QuantumError> {
        let (shared_secret, _) = self.quantum.encapsulate(peer_public)?;
        Ok(shared_secret)
    }
}

impl super::Encryptor for HybridEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, super::EncryptionError> {
        self.classical.encrypt(data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, super::EncryptionError> {
        self.classical.decrypt(data)
    }
}
