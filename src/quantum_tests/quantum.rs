//! Quantum-resistant cryptographic implementations
//!
//! This module provides implementations of post-quantum cryptographic algorithms,
//! including CRYSTALS-Kyber for key encapsulation.
//!
//! ## Overview
//!
//! The quantum module implements cryptographic algorithms that are believed to be
//! resistant to attacks from both classical and quantum computers. This is achieved
//! through the use of mathematical problems that are considered hard even for
//! quantum computers to solve.
//!
//! ## Features
//!
//! - CRYSTALS-Kyber key encapsulation mechanism (KEM)
//!   - IND-CCA2 secure key exchange
//!   - Configurable security levels (Kyber-512/768/1024)
//!   - NIST PQC Round 3 finalist
//!
//! - Hybrid encryption combining classical and quantum algorithms
//!   - Dual security from both classical and quantum-resistant algorithms
//!   - Graceful fallback if one system is compromised
//!
//! ## Usage Guidelines
//!
//! 1. For maximum security, use hybrid encryption combining both classical and
//!    quantum-resistant algorithms
//!
//! 2. Key sizes and performance characteristics differ significantly from
//!    classical algorithms:
//!    - Public keys: ~800-1500 bytes
//!    - Ciphertexts: ~700-1200 bytes
//!    - Additional computational overhead
//!
//! 3. Properly handle larger key and ciphertext sizes in protocols and storage
//!
//! ## Examples
//!
//! Basic quantum-resistant key exchange:
//!
//! ```rust
//! use tcrypt::quantum::KyberKEM;
//!
//! // Generate keypairs
//! let alice = KyberKEM::new();
//! let bob = KyberKEM::new();
//!
//! // Alice encapsulates a shared secret using Bob's public key
//! let (shared_secret, ciphertext) = alice.encapsulate(bob.public_key()).unwrap();
//!
//! // Bob decapsulates to obtain the same shared secret
//! let bob_secret = bob.decapsulate(&ciphertext).unwrap();
//!
//! assert_eq!(shared_secret, bob_secret);
//! ```
//!
//! Using hybrid encryption:
//!
//! ```rust
//! use tcrypt::quantum::HybridEncryption;
//! use tcrypt::Encryptor;
//!
//! let key = [0u8; 32];
//! let encryption = HybridEncryption::new(&key).unwrap();
//!
//! let data = b"Quantum-resistant message";
//! let encrypted = encryption.encrypt(data).unwrap();
//! let decrypted = encryption.decrypt(&encrypted).unwrap();
//!
//! assert_eq!(&decrypted, data);
//! ```

use crate::quantum::{HybridEncryption, KyberKEM};
use crate::Encryptor;

#[test]
fn test_kyber_key_exchange() {
    let alice = KyberKEM::new();
    let bob = KyberKEM::new();

    // Alice encapsulates using Bob's public key
    let (alice_ss, ciphertext) = alice.encapsulate(bob.public_key()).unwrap();

    // Bob decapsulates using the ciphertext
    let bob_ss = bob.decapsulate(&ciphertext).unwrap();

    // Verify shared secrets match
    assert_eq!(alice_ss, bob_ss);
}

#[test]
fn test_multiple_quantum_exchanges() {
    for _ in 0..100 {
        let alice = KyberKEM::new();
        let bob = KyberKEM::new();

        let (alice_ss, ciphertext) = alice.encapsulate(bob.public_key()).unwrap();
        let bob_ss = bob.decapsulate(&ciphertext).unwrap();

        assert_eq!(alice_ss, bob_ss);
    }
}

#[test]
fn test_kyber_basic_operation() {
    let alice = KyberKEM::new();
    let bob = KyberKEM::new();

    // Alice encapsulates using Bob's public key
    let (shared_secret_a, ciphertext) = alice.encapsulate(bob.public_key()).unwrap();

    // Bob decapsulates
    let shared_secret_b = bob.decapsulate(&ciphertext).unwrap();

    assert_eq!(shared_secret_a, shared_secret_b);
}

#[test]
fn test_kyber_multiple_exchanges() {
    for _ in 0..100 {
        let alice = KyberKEM::new();
        let bob = KyberKEM::new();

        let (ss_a, ct) = alice.encapsulate(bob.public_key()).unwrap();
        let ss_b = bob.decapsulate(&ct).unwrap();

        assert_eq!(ss_a, ss_b);
    }
}

#[test]
fn test_hybrid_encryption() {
    let key = [0u8; 32];
    let alice = HybridEncryption::new(&key).unwrap();
    let bob = KyberKEM::new();

    // Perform hybrid key exchange
    let shared_secret = alice.hybrid_exchange(bob.public_key()).unwrap();
    assert!(!shared_secret.is_empty());

    // Test encryption/decryption using hybrid system
    let data = b"Quantum-resistant message";
    let encrypted = alice.encrypt(data).unwrap();
    let decrypted = alice.decrypt(&encrypted).unwrap();

    assert_eq!(&decrypted, data);
}

#[test]
fn test_invalid_public_key() {
    let alice = KyberKEM::new();
    let invalid_key = vec![0u8; 32];

    assert!(alice.encapsulate(&invalid_key).is_err());
}

#[test]
fn test_invalid_ciphertext() {
    let bob = KyberKEM::new();
    let invalid_ct = vec![0u8; 32];

    assert!(bob.decapsulate(&invalid_ct).is_err());
}
