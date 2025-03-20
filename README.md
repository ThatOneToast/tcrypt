# TCrypt

`tcrypt` is a secure cryptographic library for Rust that provides tools for encryption, key exchange, and secure channel communication. It implements modern cryptographic primitives using the X25519 key exchange protocol and AES-GCM for symmetric encryption, with optional support for post-quantum cryptography.

## Features

- **Classical Cryptography**
  - Diffie-Hellman key exchange using X25519
  - AES-256-GCM symmetric encryption with authenticated encryption
  - Secure channel implementation for encrypted communications
  - Client/Server key exchange protocols with simple APIs

- **Password-Based Encryption**
  - Secure password-based encryption using Argon2id for key derivation
  - Salt management and secure format handling
  - Simple API with convenient macros

- **Quantum-Resistant Cryptography** (optional)
  - CRYSTALS-Kyber key encapsulation mechanism (KEM)
  - Hybrid classical/quantum key exchange
  - Quantum-resistant secure channels

## Usage Examples

### Basic Key Exchange and Encryption

```rust
use tcrypt::key_management::wrappers::{ClientKeyExchange, ServerKeyExchange};
use tcrypt::key_exchange::protocol::SecureChannel;

// Initialize client and server
let mut client = ClientKeyExchange::new();
let mut server = ServerKeyExchange::new();

// Perform key exchange
let client_public = client.initiate_exchange();
let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
let client_secret = client.complete_exchange(server_public).unwrap();

// Create secure channels
let client_channel = SecureChannel::new(&client_secret).unwrap();
let server_channel = SecureChannel::new(&server_secret).unwrap();

// Use channels for secure communication
let message = b"Secret message";
let encrypted = client_channel.encrypt(message).unwrap();
let decrypted = server_channel.decrypt(&encrypted).unwrap();

assert_eq!(&decrypted, message);
```

### Password-Based Encryption

```rust
use tcrypt::password::secure::{pcrypt, pdecrypt};

// Encrypt data with password
let password = "my-secure-password";
let data = "sensitive information";
let encrypted = pcrypt!(password, data).unwrap();

// Decrypt data using the same password
let decrypted = pdecrypt!(password, &encrypted).unwrap();
assert_eq!(decrypted, data.as_bytes());
```

### Quantum-Resistant Key Exchange

```rust
// This requires the "quantum" feature to be enabled
use tcrypt::quantum::wrappers::{QuantumClientExchange, QuantumServerExchange};

// Initialize quantum-resistant key exchange
let mut client = QuantumClientExchange::new();
let mut server = QuantumServerExchange::new();

// Exchange keys using CRYSTALS-Kyber
let server_public = server.public_key();
let (client_secret, ciphertext) = client.complete_exchange(server_public).unwrap();
let server_secret = server.respond_to_exchange(&ciphertext).unwrap();

assert_eq!(client_secret, server_secret);
```

## Feature Flags

- `quantum`: Enables quantum-resistant cryptography features using CRYSTALS-Kyber
- By default, only classical cryptography features are enabled

## Security Considerations

- All cryptographic operations use constant-time implementations where possible
- Proper entropy is ensured for key generation using OS-provided RNG
- Side-channel protections are in place for sensitive operations
- Memory containing sensitive data is securely zeroed when dropped

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tcrypt = "0.1.2"

# Or, to enable quantum-resistant features:
tcrypt = { version = "0.1.2", features = ["quantum"] }
```

## License

This project is licensed under the MIT License.