//! # TCrypt
//!
//! `tcrypt` is a secure cryptographic library providing tools for encryption, key exchange,
//! and secure channel communication. It implements modern cryptographic primitives using
//! the X25519 key exchange protocol and AES-GCM for symmetric encryption.
//!
//! ## Features
//!
//! - Classical cryptography:
//!   - Diffie-Hellman key exchange using X25519
//!   - AES-256-GCM symmetric encryption with authenticated encryption
//!   - Secure channel implementation
//!   - Client/Server key exchange protocols
//!
//! - Quantum-resistant cryptography (requires `quantum` feature):
//!   - CRYSTALS-Kyber key encapsulation mechanism (KEM)
//!   - Hybrid classical/quantum key exchange
//!   - Quantum-resistant secure channels
//!
//! ## Feature Flags
//!
//! - `quantum`: Enables quantum-resistant cryptography features using CRYSTALS-Kyber
//! - `default`: Classical cryptography features only
//!
//! ## Security Considerations
//!
//! - All cryptographic operations use constant-time implementations where possible
//! - Proper entropy is ensured for key generation using OS-provided RNG
//! - Side-channel protections are in place for sensitive operations
//! - Memory containing sensitive data is securely zeroed when dropped
//!
//! ## Performance
//!
//! - Classical operations are highly optimized using hardware acceleration when available
//! - Quantum-resistant operations may be computationally intensive
//! - Hybrid mode combines both classical and quantum security with reasonable performance
//!
//! ## Examples
//!
//! ### Basic Key Exchange and Encryption
//!
//! ```rust
//! use tcrypt::key_management::wrappers::{ClientKeyExchange, ServerKeyExchange};
//! use tcrypt::key_exchange::protocol::SecureChannel;
//!
//! // Initialize client and server
//! let mut client = ClientKeyExchange::new();
//! let mut server = ServerKeyExchange::new();
//!
//! // Perform key exchange
//! let client_public = client.initiate_exchange();
//! let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
//! let client_secret = client.complete_exchange(server_public).unwrap();
//!
//! // Create secure channels
//! let client_channel = SecureChannel::new(&client_secret).unwrap();
//! let server_channel = SecureChannel::new(&server_secret).unwrap();
//!
//! // Use channels for secure communication
//! let message = b"Secret message";
//! let encrypted = client_channel.encrypt(message).unwrap();
//! let decrypted = server_channel.decrypt(&encrypted).unwrap();
//!
//! assert_eq!(&decrypted, message);
//! ```
//!
//! ### Quantum-Resistant Key Exchange
//!
//! ```rust,no_run
//! # #[cfg(feature = "quantum")] {
//! use tcrypt::quantum::wrappers::{QuantumClientExchange, QuantumServerExchange};
//!
//! // Initialize quantum-resistant key exchange
//! let mut client = QuantumClientExchange::new();
//! let mut server = QuantumServerExchange::new();
//!
//! // Exchange keys using CRYSTALS-Kyber
//! let client_public = client.public_key();
//! let server_public = server.public_key();
//!
//! let (client_secret, ciphertext) = client.complete_exchange(server_public).unwrap();
//! let server_secret = server.respond_to_exchange(&ciphertext).unwrap();
//!
//! assert_eq!(client_secret, server_secret);
//! # }
//! ```
//!
//! ## Examples
//!
//! ### Basic Key Exchange
//!

#![doc(html_root_url = "https://docs.rs/tcrypt/0.1.0")]
#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

pub mod key_exchange;
pub mod key_management;
pub mod prelude;
#[cfg(feature = "quantum")]
pub mod quantum;
pub mod symetric;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[cfg(feature = "quantum")]
mod quantum_tests;

/// Trait for implementing encryption and decryption operations
pub trait Encryptor {
    /// Encrypts the provided data
    ///
    /// # Arguments
    ///
    /// * `data` - The data to encrypt
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, EncryptionError>` - The encrypted data or an error
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError>;

    /// Decrypts the provided data
    ///
    /// # Arguments
    ///
    /// * `data` - The data to decrypt
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, EncryptionError>` - The decrypted data or an error
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

/// Errors that can occur during encryption operations
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// Indicates the provided key is invalid (e.g. wrong length)
    #[error("Invalid key")]
    InvalidKey,

    /// Indicates encryption operation failed with specified error
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Indicates decryption operation failed with specified error
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}
