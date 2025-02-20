//! Prelude module providing commonly used types and traits
//!
//! This module re-exports the most commonly used types and traits from both
//! this library and its dependencies. Users can import everything from the
//! prelude with a single glob import:
//!
//! ```rust
//! use tcrypt::prelude::*;
//! ```
//!
//! # Included Types
//!
//! ## Core Types
//! - Basic encryption traits and types
//! - Key exchange protocols
//! - Symmetric encryption
//!
//! ## External Types
//! - X25519 key types
//! - AES-GCM types
//! - Common cryptographic primitives
//!
//! ## Quantum Types (optional)
//! - Kyber KEM types
//! - Hybrid encryption protocols

// Core traits and types
pub use crate::Encryptor;

// Classical cryptography
pub use crate::key_exchange::{protocol::SecureChannel, DHKeyExchange};
pub use crate::key_management::wrappers::{ClientKeyExchange, ServerKeyExchange};
pub use crate::symetric::AESEncryption;

// Error types
pub use crate::key_management::KeyExchangeError;
pub use crate::EncryptionError;

// Re-export commonly used x25519 types
pub use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

// Re-export AES-GCM types
pub use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};

// Re-export common crypto primitive types
pub use sha2::{Digest, Sha256};

// Quantum-resistant cryptography (only when quantum feature is enabled)
#[cfg(feature = "quantum")]
pub use crate::quantum::{
    wrappers::{HybridKeyExchange, QuantumClientExchange, QuantumServerExchange},
    HybridEncryption, KyberKEM, QuantumError,
};


