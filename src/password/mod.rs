// tcrypt/src/password/mod.rs
//! Password-based encryption module
//!
//! This module provides functionality for encrypting and decrypting data
//! using a password rather than requiring a full key exchange.


pub mod secure;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use sha2::{Digest, Sha256};

use crate::{symetric::AESEncryption, EncryptionError, Encryptor};

/// Password-based encryption using Argon2 key derivation
#[derive(Clone)]
pub struct PasswordEncryption {
    cipher: AESEncryption,
}

impl PasswordEncryption {
    /// Creates a new password-based encryption instance
    ///
    /// This function derives an encryption key from the provided password
    /// using Argon2id - a secure password hashing algorithm designed to be
    /// resistant to both computation-intensive and memory-intensive attacks.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the encryption key from
    ///
    /// # Examples
    ///
    /// ```
    /// use tcrypt::password::PasswordEncryption;
    /// use tcrypt::Encryptor;
    ///
    /// let encryption = PasswordEncryption::new("my-secure-password").unwrap();
    /// let data = b"Secret data";
    /// let encrypted = encryption.encrypt(data).unwrap();
    /// let decrypted = encryption.decrypt(&encrypted).unwrap();
    ///
    /// assert_eq!(&decrypted, data);
    /// ```
    pub fn new(password: &str) -> Result<Self, EncryptionError> {
        // Generate a random salt
        let salt = SaltString::generate(&mut OsRng);
        
        // Hash the password using Argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| EncryptionError::InvalidKey)?
            .to_string();
            
        // Generate a 32-byte key by hashing the Argon2 output
        let mut hasher = Sha256::new();
        hasher.update(password_hash.as_bytes());
        let key = hasher.finalize();
        
        // Create AES encryption with derived key
        let cipher = AESEncryption::new(&key)?;
        
        Ok(Self { cipher })
    }
    
    /// Creates encryption from existing raw key
    ///
    /// This is mostly for internal use and testing.
    pub fn from_key(key: &[u8]) -> Result<Self, EncryptionError> {
        let cipher = AESEncryption::new(key)?;
        Ok(Self { cipher })
    }
}

impl Encryptor for PasswordEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.cipher.encrypt(data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        self.cipher.decrypt(data)
    }
}