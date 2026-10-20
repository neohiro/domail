//! Integration tests for MX Node transport activation

#[tokio::test]
async fn mx_transport_activate_all() {
    use mx_node::{
        config::TransportConfig,
        transport::{init_transports, TransportManager},
    };
    let configs = vec![
        TransportConfig {
            id: "direct".to_string(),
            enabled: true,
            options: std::collections::HashMap::new(),
        },
        TransportConfig {
            id: "tor".to_string(),
            enabled: true,
            options: std::collections::HashMap::new(),
        },
        TransportConfig {
            id: "nostr".to_string(),
            enabled: true,
            options: std::collections::HashMap::new(),
        },
        TransportConfig {
            id: "lora".to_string(),
            enabled: true,
            options: std::collections::HashMap::new(),
        },
    ];
    let mgr = init_transports(configs).await.unwrap();
    mgr.activate_all().await.unwrap();
}
