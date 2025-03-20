// tcrypt/src/password/secure.rs
//! Secure password-based encryption with salt management
//!
//! This module enhances the basic password encryption with proper
//! salt management and format handling.

use aes_gcm::aead::OsRng;
use argon2::{
    password_hash::SaltString,
    Argon2, PasswordHasher,
};
use sha2::{Digest, Sha256};

use crate::{symetric::AESEncryption, EncryptionError, Encryptor};

pub use crate::{pcrypt, pdecrypt};

/// Enhanced password-based encryption with automatic salt management
pub struct SecurePasswordEncryption {}



impl SecurePasswordEncryption {
    /// Encrypts data with a password
    ///
    /// This function handles all aspects of secure password-based encryption:
    /// - Generates a random salt
    /// - Derives a secure key using Argon2id
    /// - Encrypts the data using AES-GCM
    /// - Stores the salt with the encrypted data
    ///
    /// # Arguments
    ///
    /// * `password` - Password to encrypt the data with
    /// * `data` - Data to encrypt
    ///
    /// # Returns
    ///
    /// A Vec<u8> containing the encrypted data with embedded salt
    ///
    /// # Examples
    ///
    /// ```
    /// use tcrypt::password::secure::SecurePasswordEncryption;
    ///
    /// let data = b"Secret message";
    /// let password = "my-secure-password";
    ///
    /// // Encrypt data with password
    /// let encrypted = SecurePasswordEncryption::encrypt_with_password(password, data).unwrap();
    ///
    /// // Decrypt data with the same password
    /// let decrypted = SecurePasswordEncryption::decrypt_with_password(password, &encrypted).unwrap();
    ///
    /// assert_eq!(&decrypted, data);
    /// ```
    pub fn encrypt_with_password(password: &str, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        // Generate random salt
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();
        
        // Derive key using Argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| EncryptionError::InvalidKey)?
            .to_string();
            
        // Generate 32-byte key by hashing the Argon2 output
        let mut hasher = Sha256::new();
        hasher.update(password_hash.as_bytes());
        let key = hasher.finalize();
        
        // Create AES encryption with derived key
        let cipher = AESEncryption::new(&key)?;
        let encrypted = cipher.encrypt(data)?;
        
        // Combine salt with encrypted data
        let mut result = Vec::with_capacity(salt_bytes.len() + 1 + encrypted.len());
        result.push(salt_bytes.len() as u8); // First byte is salt length
        result.extend_from_slice(salt_bytes);
        result.extend_from_slice(&encrypted);
        
        Ok(result)
    }
    
    /// Decrypts data that was encrypted with a password
    ///
    /// This function extracts the salt from the encrypted data,
    /// derives the same key using the provided password,
    /// and then decrypts the data.
    ///
    /// # Arguments
    ///
    /// * `password` - Password used for encryption
    /// * `encrypted_data` - Data previously encrypted with `encrypt_with_password`
    ///
    /// # Returns
    ///
    /// The original decrypted data
    pub fn decrypt_with_password(password: &str, encrypted_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if encrypted_data.is_empty() {
            return Err(EncryptionError::DecryptionFailed("Empty data".into()));
        }
        
        // Extract salt length and salt
        let salt_len = encrypted_data[0] as usize;
        if encrypted_data.len() < salt_len + 1 {
            return Err(EncryptionError::DecryptionFailed("Invalid data format".into()));
        }
        
        let salt_bytes = &encrypted_data[1..salt_len+1];
        let salt = std::str::from_utf8(salt_bytes)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid salt".into()))?;
        
        // Recreate salt string
        let salt = SaltString::from_b64(salt)
            .map_err(|_| EncryptionError::DecryptionFailed("Invalid salt format".into()))?;
        
        // Derive the same key
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| EncryptionError::DecryptionFailed("Key derivation failed".into()))?
            .to_string();
            
        // Hash to get the 32-byte key
        let mut hasher = Sha256::new();
        hasher.update(password_hash.as_bytes());
        let key = hasher.finalize();
        
        // Create cipher and decrypt
        let cipher = AESEncryption::new(&key)?;
        cipher.decrypt(&encrypted_data[salt_len+1..])
    }
}

/// Convenience macro for encrypting data with a password
///
/// # Examples
///
/// ```
/// # use tcrypt::password::secure::pcrypt;
/// let encrypted = pcrypt!("my-password", "sensitive data").unwrap();
/// ```
#[macro_export]
macro_rules! pcrypt {
    ($password:expr, $data:expr) => {
        $crate::password::secure::SecurePasswordEncryption::encrypt_with_password(
            $password,
            $data.as_ref()
        )
    };
}

/// Convenience macro for decrypting data with a password
///
/// # Examples
///
/// ```
/// # use tcrypt::password::secure::{pcrypt, pdecrypt};
/// # let password = "my-password";
/// # let data = "sensitive data";
/// # let encrypted = pcrypt!(password, data).unwrap();
/// let decrypted = pdecrypt!(password, &encrypted).unwrap();
/// assert_eq!(decrypted, data.as_bytes());
/// ```
#[macro_export]
macro_rules! pdecrypt {
    ($password:expr, $data:expr) => {
        $crate::password::secure::SecurePasswordEncryption::decrypt_with_password(
            $password,
            $data
        )
    };
}

