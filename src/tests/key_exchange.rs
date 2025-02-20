use crate::key_management::wrappers::{ClientKeyExchange, ServerKeyExchange};


#[test]
fn test_basic_key_exchange() {
    let mut client = ClientKeyExchange::new();
    let mut server = ServerKeyExchange::new();

    // Client initiates exchange
    let client_public = client.initiate_exchange();

    // Server responds
    let (server_public, server_secret) = server
        .respond_to_exchange(client_public)
        .expect("Server exchange failed");

    // Client completes exchange
    let client_secret = client
        .complete_exchange(server_public)
        .expect("Client exchange failed");

    // Verify shared secrets match
    assert_eq!(client_secret, server_secret);
}

#[test]
fn test_multiple_exchanges() {
    for _ in 0..100 {
        let mut client = ClientKeyExchange::new();
        let mut server = ServerKeyExchange::new();

        let client_public = client.initiate_exchange();
        let (server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();
        let client_secret = client.complete_exchange(server_public).unwrap();

        assert_eq!(client_secret, server_secret);
    }
}

#[test]
fn test_key_uniqueness() {
    let mut previous_secrets = Vec::new();

    for _ in 0..10 {
        let client = ClientKeyExchange::new();
        let mut server = ServerKeyExchange::new();

        let client_public = client.initiate_exchange();
        let (_server_public, server_secret) = server.respond_to_exchange(client_public).unwrap();

        // Ensure this secret is unique
        assert!(!previous_secrets.contains(&server_secret));
        previous_secrets.push(server_secret);
    }
}
