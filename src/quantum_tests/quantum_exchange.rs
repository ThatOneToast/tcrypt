use crate::quantum::wrappers::{HybridKeyExchange, QuantumClientExchange, QuantumServerExchange};
#[test]
fn test_quantum_exchange() {
    let mut client = QuantumClientExchange::new();
    let mut server = QuantumServerExchange::new();

    // Get public keys
    let _client_public = client.public_key().to_vec();
    let server_public = server.public_key().to_vec();

    // Client completes their part
    let (client_secret, ciphertext) = client.complete_exchange(&server_public).unwrap();

    // Server responds
    let server_secret = server.respond_to_exchange(&ciphertext).unwrap();

    // Verify secrets match
    assert_eq!(client_secret, server_secret);
}

#[test]
fn test_multiple_quantum_exchanges() {
    for _ in 0..100 {
        let mut client = QuantumClientExchange::new();
        let mut server = QuantumServerExchange::new();

        let server_public = server.public_key().to_vec();
        let (client_secret, ciphertext) = client.complete_exchange(&server_public).unwrap();
        let server_secret = server.respond_to_exchange(&ciphertext).unwrap();

        assert_eq!(client_secret, server_secret);
    }
}

#[test]
fn test_hybrid_exchange() {
    let mut alice = HybridKeyExchange::new();
    let mut bob = HybridKeyExchange::new();

    // Get public keys
    let (alice_quantum_pk, alice_classical_pk) = alice.public_keys();
    let (bob_quantum_pk, bob_classical_pk) = bob.public_keys();

    // Clone the public keys to avoid borrow issues
    let alice_quantum = alice_quantum_pk.to_vec();
    let bob_quantum = bob_quantum_pk.to_vec();
    let alice_classical = *alice_classical_pk;
    let bob_classical = *bob_classical_pk;

    // Alice initiates the exchange
    let (alice_secret, alice_ciphertext) = alice
        .perform_exchange(&bob_quantum, &bob_classical, None)
        .unwrap();

    // Bob completes the exchange using Alice's ciphertext
    let (bob_secret, _) = bob
        .perform_exchange(
            &alice_quantum,
            &alice_classical,
            alice_ciphertext.as_deref(),
        )
        .unwrap();

    // Verify combined secrets match
    assert_eq!(alice_secret, bob_secret);
}

#[test]
fn test_invalid_quantum_exchange() {
    let mut client = QuantumClientExchange::new();
    let invalid_key = vec![0u8; 32];

    assert!(client.complete_exchange(&invalid_key).is_err());
}
