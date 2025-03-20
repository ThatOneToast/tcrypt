use crate::password::{PasswordEncryption, secure::SecurePasswordEncryption};
use crate::Encryptor;

#[test]
fn test_basic_password_encryption() {
    let password = "secure-password-123";
    let encryption = PasswordEncryption::new(password).unwrap();
    
    let data = b"This is a secret message";
    let encrypted = encryption.encrypt(data).unwrap();
    let decrypted = encryption.decrypt(&encrypted).unwrap();
    
    assert_eq!(&decrypted, data);
}

#[test]
fn test_different_passwords() {
    let password1 = "password1";
    let password2 = "password2";
    
    let encryption1 = PasswordEncryption::new(password1).unwrap();
    let encryption2 = PasswordEncryption::new(password2).unwrap();
    
    let data = b"Secret data";
    let encrypted = encryption1.encrypt(data).unwrap();
    
    // Trying to decrypt with different password should fail
    assert!(encryption2.decrypt(&encrypted).is_err());
}

#[test]
fn test_secure_password_encryption() {
    let password = "my-secure-password";
    let data = b"This is a secret message";
    
    // Encrypt with password
    let encrypted = SecurePasswordEncryption::encrypt_with_password(password, data).unwrap();
    
    // Decrypt with same password
    let decrypted = SecurePasswordEncryption::decrypt_with_password(password, &encrypted).unwrap();
    
    assert_eq!(&decrypted, data);
}

#[test]
fn test_secure_password_wrong_password() {
    let correct_password = "correct-password";
    let wrong_password = "wrong-password";
    let data = b"Secret data needs protection";
    
    let encrypted = SecurePasswordEncryption::encrypt_with_password(correct_password, data).unwrap();
    
    // Should fail with wrong password
    assert!(SecurePasswordEncryption::decrypt_with_password(wrong_password, &encrypted).is_err());
}

#[test]
fn test_secure_password_empty_data() {
    let password = "password";
    let data = b"";
    
    // Empty data should encrypt/decrypt correctly
    let encrypted = SecurePasswordEncryption::encrypt_with_password(password, data).unwrap();
    let decrypted = SecurePasswordEncryption::decrypt_with_password(password, &encrypted).unwrap();
    
    assert_eq!(&decrypted, data);
}

#[test]
fn test_secure_password_large_data() {
    let password = "password";
    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    
    let encrypted = SecurePasswordEncryption::encrypt_with_password(password, &data).unwrap();
    let decrypted = SecurePasswordEncryption::decrypt_with_password(password, &encrypted).unwrap();
    
    assert_eq!(decrypted, data);
}