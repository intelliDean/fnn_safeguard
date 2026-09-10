use fnn_safeguard::commands::inspect::{InspectCommand, InspectOptions};
use serde_json::json;
use std::fs;
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_inspect_against_mock_fnn() {
    let mock_server = MockServer::start().await;

    // 1. Mock node_info with hexadecimal numerical fields and mainnet chain hash
    let node_info_response = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "version": "v0.9.0",
            "commit_hash": "e6cb7ac",
            "pubkey": "03ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "node_name": "fiber-validator-01",
            "addresses": ["/ip4/127.0.0.1/tcp/8228"],
            "chain_hash": "0x92b16a0e26815e04e7f331399415615f225626aa33719c0950dd2c0f016ddf67",
            "channel_count": "0x2",
            "pending_channel_count": "0x0",
            "peers_count": "0x4"
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"node_info\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(node_info_response))
        .mount(&mock_server)
        .await;

    // 2. Mock list_channels with real ChannelReady and Stale adjacently-tagged states
    let list_channels_response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "channels": [
                {
                    "channel_id": "0xch1",
                    "state": {
                        "state_name": "ChannelReady"
                    }
                },
                {
                    "channel_id": "0xch2",
                    "state": {
                        "state_name": "Stale"
                    }
                }
            ]
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"list_channels\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_channels_response))
        .mount(&mock_server)
        .await;

    // 3. Mock list_payments with cursor pagination and hexadecimal created_at
    let list_payments_page1 = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "payments": [
                {
                    "payment_hash": "0xpay1",
                    "status": "Success",
                    "created_at": "0x191e4f29f40"
                }
            ],
            "last_cursor": "page2_cursor"
        }
    });

    let list_payments_page2 = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "payments": [
                {
                    "payment_hash": "0xpay2",
                    "status": "Success",
                    "created_at": 1725999996736u64
                }
            ],
            "last_cursor": null
        }
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"list_payments\""))
        .and(body_string_contains("\"after\":\"page2_cursor\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_payments_page2))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"list_payments\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_payments_page1))
        .mount(&mock_server)
        .await;

    // 4. Create mock config file with secrets
    let temp_dir = TempDir::new().unwrap();
    let config_file = temp_dir.path().join("config.yml");
    fs::write(
        &config_file,
        "rpc:\n  listening_addr: 127.0.0.1:8227\n  auth_token: super_secret_token_12345\nckb:\n  password: private_wallet_password_xyz\n",
    )
    .unwrap();

    // 5. Execute actual InspectCommand
    let opts = InspectOptions {
        rpc_url: mock_server.uri(),
        auth_token: Some("super_secret_token_12345".to_string()),
        config_path: Some(config_file.clone()),
        node_dir: Some(temp_dir.path().to_path_buf()),
        json_output: true,
    };

    let report = InspectCommand::run(opts)
        .await
        .expect("InspectCommand must succeed against real mock FNN RPC");

    // 6. Assert live node inventory inspection results
    assert_eq!(
        report.node_public_key,
        "03ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    );
    assert_eq!(report.fnn_version, "v0.9.0");
    assert_eq!(report.fnn_commit, "e6cb7ac");
    assert_eq!(report.network, "mainnet");
    assert_eq!(report.ready_channels, 1);
    assert_eq!(report.stale_channels, 1);
    assert_eq!(report.total_channels, 2);
    assert_eq!(report.total_payments, 2);

    // 7. Verify config secret redaction
    let (hash, sanitized) =
        fnn_safeguard::config::ConfigSanitizer::sanitize_and_hash(&config_file).unwrap();
    assert!(
        !sanitized.contains("super_secret_token_12345"),
        "Auth token was not redacted!"
    );
    assert!(
        !sanitized.contains("private_wallet_password_xyz"),
        "Password was not redacted!"
    );
    assert!(sanitized.contains("[REDACTED]"));
    assert_eq!(report.config_checksum, hash);
}
