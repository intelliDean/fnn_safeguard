use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    pub params: T,
}

impl<T: Serialize> JsonRpcRequest<T> {
    pub fn new(id: u64, method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<T>,
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl Display for JsonRpcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "RPC Error (code {}): {}", self.code, self.message)
    }
}

impl Error for JsonRpcError {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeInfoResult {
    pub version: String,
    pub commit_hash: String,
    pub pubkey: String,
    pub node_name: Option<String>,
    pub addresses: Vec<String>,
    pub chain_hash: String,
    pub channel_count: u32,
    pub pending_channel_count: u32,
    pub peers_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub state: ChannelStateInfo,
    pub peer_id: Option<String>,
    pub local_balance: Option<String>,
    pub remote_balance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ChannelStateInfo {
    Simple(String),
    Structured { state_name: String },
}

impl ChannelStateInfo {
    pub fn as_str(&self) -> &str {
        match self {
            ChannelStateInfo::Simple(s) => s.as_str(),
            ChannelStateInfo::Structured { state_name } => state_name.as_str(),
        }
    }
}

impl Default for ChannelStateInfo {
    fn default() -> Self {
        ChannelStateInfo::Simple("Unknown".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListChannelsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_closed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListChannelsResult {
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PaymentInfo {
    pub payment_hash: String,
    pub status: String,
    pub created_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListPaymentsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListPaymentsResult {
    pub payments: Vec<PaymentInfo>,
}
