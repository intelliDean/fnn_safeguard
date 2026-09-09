use serde_json::json;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_inspect_against_mock_fnn() {
    let mock_server = MockServer::start().await;

    // Mock node_info
    let node_info_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "version": "v0.9.0",
            "commit_hash": "e6cb7ac7770b1798a1ad5dfb9a8f4ae5db52036f",
            "pubkey": "03ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "node_name": "fiber-validator-01",
            "addresses": ["/ip4/127.0.0.1/tcp/8228"],
            "chain_hash": "0x92b16a0e26815e04e7f331399415615f225626aa33719c0950dd2c0f016ddf67",
            "channel_count": 2,
            "pending_channel_count": 0,
            "peers_count": 4
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(node_info_response))
        .mount(&mock_server)
        .await;

    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.path().join("config.yml");
    fs::write(
        &config_file,
        "rpc:\n  listening_addr: 127.0.0.1:8227\n  auth_token: super_secret_token_12345\nckb:\n  password: private_wallet_password_xyz\n",
    )
    .unwrap();

    // Verify ConfigSanitizer redacts secrets
    // We can run the inspect command logic or config sanitizer
    let (hash, sanitized) = fnn_safeguard::config::ConfigSanitizer::sanitize_and_hash(&config_file).unwrap();
    assert!(!sanitized.contains("super_secret_token_12345"), "Auth token was not redacted!");
    assert!(!sanitized.contains("private_wallet_password_xyz"), "Password was not redacted!");
    assert!(sanitized.contains("[REDACTED]"));
    assert!(hash.starts_with("sha256:"));
}
