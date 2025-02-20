use crate::{
    key_exchange::protocol::SecureChannel,
    key_management::wrappers::{ClientKeyExchange, ServerKeyExchange},
    symetric::AESEncryption,
    EncryptionError, Encryptor,
};

pub mod key_exchange;

#[test]
fn test_basic_encryption_decryption() {
    let key = [0u8; 32];
    let encryptor = AESEncryption::new(&key).unwrap();

    let data = b"Hello, World!";
    let encrypted = encryptor.encrypt(data).unwrap();
    let decrypted = encryptor.decrypt(&encrypted).unwrap();

    assert_eq!(&decrypted, data);
}

#[test]
fn test_empty_data_encryption() {
    let key = [0u8; 32];
    let encryptor = AESEncryption::new(&key).unwrap();

    let data = b"";
    let encrypted = encryptor.encrypt(data).unwrap();
    let decrypted = encryptor.decrypt(&encrypted).unwrap();

    assert_eq!(&decrypted, data);
}

#[test]
fn test_large_data_encryption() {
    let key = [0u8; 32];
    let encryptor = AESEncryption::new(&key).unwrap();

    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let encrypted = encryptor.encrypt(&data).unwrap();
    let decrypted = encryptor.decrypt(&encrypted).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn test_invalid_key_sizes() {
    let short_key = [0u8; 16];
    assert!(matches!(
        AESEncryption::new(&short_key),
        Err(EncryptionError::InvalidKey)
    ));

    let long_key = [0u8; 64];
    assert!(matches!(
        AESEncryption::new(&long_key),
        Err(EncryptionError::InvalidKey)
    ));
}

#[test]
fn test_nonce_management() {
    let key = [0u8; 32];
    let mut encryptor = AESEncryption::new(&key).unwrap();

    let initial_nonce = encryptor.current_nonce().clone();

    // Test nonce update
    let new_nonce = [1u8; 12];
    assert!(encryptor.update_nonce(&new_nonce).is_ok());
    assert_ne!(encryptor.current_nonce(), &initial_nonce);

    // Test invalid nonce size
    let invalid_nonce = [1u8; 16];
    assert!(matches!(
        encryptor.update_nonce(&invalid_nonce),
        Err(EncryptionError::InvalidKey)
    ));
}

#[test]
fn test_full_secure_communication() {
    // Perform key exchange
    let mut client = ClientKeyExchange::new();
    let mut server = ServerKeyExchange::new();

    let client_public = client.initiate_exchange();
    let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
    let client_secret = client.complete_exchange(server_public).unwrap();

    // Create secure channels
    let client_channel = SecureChannel::new(&client_secret).unwrap();
    let server_channel = SecureChannel::new(&server_secret).unwrap();

    // Test communication
    let original_message = b"Secret message for secure transmission";
    let encrypted = client_channel.encrypt(original_message).unwrap();
    let decrypted = server_channel.decrypt(&encrypted).unwrap();

    assert_eq!(&decrypted, original_message);
}

#[test]
fn test_bidirectional_communication() {
    let mut client = ClientKeyExchange::new();
    let mut server = ServerKeyExchange::new();

    // Establish connection
    let client_public = client.initiate_exchange();
    let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
    let client_secret = client.complete_exchange(server_public).unwrap();

    let client_channel = SecureChannel::new(&client_secret).unwrap();
    let server_channel = SecureChannel::new(&server_secret).unwrap();

    // Client to Server
    let client_message = b"Hello from client";
    let encrypted_client = client_channel.encrypt(client_message).unwrap();
    let decrypted_client = server_channel.decrypt(&encrypted_client).unwrap();
    assert_eq!(&decrypted_client, client_message);

    // Server to Client
    let server_message = b"Hello from server";
    let encrypted_server = server_channel.encrypt(server_message).unwrap();
    let decrypted_server = client_channel.decrypt(&encrypted_server).unwrap();
    assert_eq!(&decrypted_server, server_message);
}

#[test]
fn test_multiple_messages() {
    let mut client = ClientKeyExchange::new();
    let mut server = ServerKeyExchange::new();

    // Establish connection
    let client_public = client.initiate_exchange();
    let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
    let client_secret = client.complete_exchange(server_public).unwrap();

    let client_channel = SecureChannel::new(&client_secret).unwrap();
    let server_channel = SecureChannel::new(&server_secret).unwrap();

    // Test multiple messages
    let messages = vec![
        b"Message 1".to_vec(),
        b"Message 2".to_vec(),
        b"Message 3".to_vec(),
    ];

    for msg in messages {
        let encrypted = client_channel.encrypt(&msg).unwrap();
        let decrypted = server_channel.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
