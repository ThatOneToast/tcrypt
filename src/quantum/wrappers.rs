use super::{KyberKEM, QuantumError};

#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("Quantum exchange error: {0}")]
    QuantumError(#[from] QuantumError),
    #[error("Classical exchange error: {0}")]
    ClassicalError(#[from] crate::key_management::KeyExchangeError),
}

/// Client-side wrapper for quantum-resistant key exchange
pub struct QuantumClientExchange {
    kem: KyberKEM,
    shared_secret: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

impl QuantumClientExchange {
    /// Creates a new quantum client exchange instance
    pub fn new() -> Self {
        let kem = KyberKEM::new();
        let public_key = kem.public_key().to_vec();
        Self {
            kem,
            shared_secret: None,
            public_key,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Initiates the quantum key exchange by providing the public key
    pub fn initiate_exchange(&self) -> &[u8] {
        self.kem.public_key()
    }

    /// Completes the exchange using the server's public key and ciphertext
    pub fn complete_exchange(
        &mut self,
        server_public: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), QuantumError> {
        let (shared_secret, ciphertext) = self.kem.encapsulate(server_public)?;
        self.shared_secret = Some(shared_secret.clone());
        Ok((shared_secret, ciphertext))
    }

    /// Retrieves the current shared secret if available
    pub fn get_shared_secret(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }
}

/// Server-side wrapper for quantum-resistant key exchange
pub struct QuantumServerExchange {
    kem: KyberKEM,
    shared_secret: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

impl QuantumServerExchange {
    /// Creates a new quantum server exchange instance
    pub fn new() -> Self {
        let kem = KyberKEM::new();
        let public_key = kem.public_key().to_vec();
        Self {
            kem,
            shared_secret: None,
            public_key,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Responds to a client's exchange request
    pub fn respond_to_exchange(
        &mut self,
        client_ciphertext: &[u8],
    ) -> Result<Vec<u8>, QuantumError> {
        let shared_secret = self.kem.decapsulate(client_ciphertext)?;
        self.shared_secret = Some(shared_secret.clone());
        Ok(shared_secret)
    }

    /// Retrieves the current shared secret if available
    pub fn get_shared_secret(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }
}

/// Hybrid exchange wrapper combining classical and quantum key exchange
pub struct HybridKeyExchange {
    quantum: KyberKEM,
    classical: crate::key_management::KeyExchange,
    shared_secret: Option<Vec<u8>>,
    quantum_public: Vec<u8>,
    classical_public: x25519_dalek::PublicKey,
}

impl HybridKeyExchange {
    /// Creates a new hybrid key exchange instance
    pub fn new() -> Self {
        let quantum = KyberKEM::new();
        let classical = crate::key_management::KeyExchange::new();
        let quantum_public = quantum.public_key().to_vec();
        let classical_public = *classical.public_key();

        Self {
            quantum,
            classical,
            shared_secret: None,
            quantum_public,
            classical_public,
        }
    }

    /// Returns both quantum and classical public keys
    pub fn public_keys(&self) -> (&[u8], &x25519_dalek::PublicKey) {
        (self.quantum.public_key(), self.classical.public_key())
    }

    /// Performs hybrid key exchange
    pub fn perform_exchange(
        &mut self,
        peer_quantum_public: &[u8],
        peer_classical_public: &x25519_dalek::PublicKey,
        peer_ciphertext: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), ExchangeError> {
        let (quantum_secret, ciphertext) = if let Some(ct) = peer_ciphertext {
            // If we received a ciphertext, we're the responder
            (self.quantum.decapsulate(ct)?, None)
        } else {
            // If we didn't receive a ciphertext, we're the initiator
            let (ss, ct) = self.quantum.encapsulate(peer_quantum_public)?;
            (ss, Some(ct))
        };

        // Perform classical exchange
        let classical_secret = self
            .classical
            .compute_shared_secret(peer_classical_public)
            .map_err(ExchangeError::ClassicalError)?;

        // Combine secrets consistently
        let mut combined_secret = Vec::with_capacity(quantum_secret.len() + classical_secret.len());
        combined_secret.extend_from_slice(&quantum_secret);
        combined_secret.extend_from_slice(&classical_secret);

        self.shared_secret = Some(combined_secret.clone());
        Ok((combined_secret, ciphertext))
    }

    /// Retrieves the combined shared secret if available
    pub fn get_shared_secret(&self) -> Option<&[u8]> {
        self.shared_secret.as_deref()
    }
}
