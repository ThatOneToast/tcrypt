use crate::{symetric::AESEncryption, Encryptor};

/// Provides encrypted communication channel using shared secret
#[derive(Clone)]
pub struct SecureChannel {
    encryption: AESEncryption,
}

impl SecureChannel {
    /// Creates new secure channel from shared secret
    pub fn new(shared_secret: &[u8]) -> Result<Self, crate::EncryptionError> {
        Ok(Self {
            encryption: AESEncryption::new(shared_secret)?,
        })
    }

    /// Encrypts data for secure transmission
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, crate::EncryptionError> {
        self.encryption.encrypt(data)
    }

    /// Decrypts received encrypted data
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, crate::EncryptionError> {
        self.encryption.decrypt(data)
    }
}
