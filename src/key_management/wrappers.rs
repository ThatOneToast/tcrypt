use x25519_dalek::PublicKey;

use super::{KeyExchange, KeyExchangeError};

/// Client-side implementation of key exchange
#[derive(Clone)]
pub struct ClientKeyExchange {
    exchange: KeyExchange,
}

impl ClientKeyExchange {
    /// Creates new client key exchange instance
    pub fn new() -> Self {
        Self {
            exchange: KeyExchange::new(),
        }
    }

    /// Initiates exchange by providing client's public key
    pub fn initiate_exchange(&self) -> &PublicKey {
        self.exchange.public_key()
    }

    /// Completes exchange using server's public key
    pub fn complete_exchange(
        &mut self,
        server_public: &PublicKey,
    ) -> Result<Vec<u8>, KeyExchangeError> {
        self.exchange.compute_shared_secret(server_public)
    }
}

/// Server-side implementation of key exchange
pub struct ServerKeyExchange {
    exchange: KeyExchange,
}

impl ServerKeyExchange {
    /// Creates new server key exchange instance
    pub fn new() -> Self {
        Self {
            exchange: KeyExchange::new(),
        }
    }

    /// Responds to client exchange request with server public key and secret
    pub fn respond_to_exchange(
        &mut self,
        client_public: &PublicKey,
    ) -> Result<(&PublicKey, Vec<u8>), KeyExchangeError> {
        let shared_secret = self.exchange.compute_shared_secret(client_public)?;
        Ok((self.exchange.public_key(), shared_secret))
    }
}
