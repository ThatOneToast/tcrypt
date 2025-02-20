//! Symmetric encryption module implementing AES-GCM
//!
//! Provides secure symmetric encryption using AES-256-GCM with
//! proper nonce management and authenticated encryption.

use aes_gcm::{
    aead::{consts::U12, Aead},
    Aes256Gcm, Key, KeyInit, Nonce,
};

use crate::{EncryptionError, Encryptor};

/// Implements AES-256-GCM symmetric encryption
///
/// # Examples
///
/// ```
/// use tcrypt::symetric::AESEncryption;
///
/// let key = [0u8; 32];
/// let encryption = AESEncryption::new(&key).unwrap();
/// let data = b"Hello, world!";
/// let encrypted = encryption.encrypt(data).unwrap();
/// let decrypted = encryption.decrypt(&encrypted).unwrap();
/// assert_eq!(&decrypted, data);
/// ```
pub struct AESEncryption {
    cipher: Aes256Gcm,
    nonce: Nonce<U12>,
}

impl AESEncryption {
    /// Creates new AES-256-GCM encryption instance with given key
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKey);
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::<U12>::from_slice(&[0u8; 12]).clone();

        Ok(Self { cipher, nonce })
    }

    /// Returns current nonce used for encryption
    pub fn current_nonce(&self) -> &Nonce<U12> {
        &self.nonce
    }

    /// Returns current nonce as raw bytes
    pub fn nonce_bytes(&self) -> [u8; 12] {
        self.nonce.as_slice().try_into().unwrap()
    }

    /// Updates the nonce
    pub fn update_nonce(&mut self, new_nonce: &[u8]) -> Result<(), EncryptionError> {
        if new_nonce.len() != 12 {
            return Err(EncryptionError::InvalidKey);
        }
        self.nonce = *Nonce::<U12>::from_slice(new_nonce);
        Ok(())
    }
}

impl Encryptor for AESEncryption {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let encrypted = self
            .cipher
            .encrypt(&self.nonce, data)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to encrypted data
        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(self.nonce.as_slice());
        result.extend(encrypted);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::DecryptionFailed(
                "Invalid data length".into(),
            ));
        }

        let (nonce_bytes, encrypted) = data.split_at(12);
        let nonce = Nonce::<U12>::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }
}
