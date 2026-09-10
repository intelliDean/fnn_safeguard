use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

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
#[serde(bound(deserialize = "T: DeserializeOwned"))]
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

/// Custom serde module for numeric fields that may be serialized as hexadecimal strings (e.g. "0x2")
/// or native integers (e.g. 2).
pub mod hex_or_int_u32 {
    use super::*;

    pub fn serialize<S>(val: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", val))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| serde::de::Error::custom("invalid integer for u32")),
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u32::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
                } else {
                    trimmed.parse::<u32>().map_err(serde::de::Error::custom)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected integer or hex string for u32",
            )),
        }
    }
}

pub mod hex_or_int_u64 {
    use super::*;

    pub fn serialize<S>(val: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", val))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| serde::de::Error::custom("invalid integer for u64")),
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
                } else {
                    trimmed.parse::<u64>().map_err(serde::de::Error::custom)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected integer or hex string for u64",
            )),
        }
    }
}

pub mod hex_or_int_u128 {
    use super::*;

    pub fn serialize<S>(val: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", val))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::Number(n) => n
                .as_u64()
                .map(|v| v as u128)
                .ok_or_else(|| serde::de::Error::custom("invalid integer for u128")),
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u128::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
                } else {
                    trimmed.parse::<u128>().map_err(serde::de::Error::custom)
                }
            }
            _ => Err(serde::de::Error::custom(
                "expected integer or hex string for u128",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeInfoResult {
    pub version: String,
    pub commit_hash: String,
    pub pubkey: String,
    #[serde(default)]
    pub node_name: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    pub chain_hash: String,
    #[serde(with = "hex_or_int_u32", default)]
    pub channel_count: u32,
    #[serde(with = "hex_or_int_u32", default)]
    pub pending_channel_count: u32,
    #[serde(with = "hex_or_int_u32", default)]
    pub peers_count: u32,
}

/// Official ChannelState variants matching Fiber v0.9.x
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state_name", content = "state_flags")]
pub enum ChannelState {
    NegotiatingFunding(Option<serde_json::Value>),
    CollaboratingFundingTx(Option<serde_json::Value>),
    SigningCommitment(Option<serde_json::Value>),
    AwaitingTxSignatures(Option<serde_json::Value>),
    AwaitingChannelReady(Option<serde_json::Value>),
    ChannelReady,
    ShuttingDown(Option<serde_json::Value>),
    Closed(Option<serde_json::Value>),
    Stale,
    #[serde(other)]
    Unknown,
}

impl ChannelState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelState::ChannelReady => "ChannelReady",
            ChannelState::Stale => "Stale",
            ChannelState::NegotiatingFunding(_) => "NegotiatingFunding",
            ChannelState::CollaboratingFundingTx(_) => "CollaboratingFundingTx",
            ChannelState::SigningCommitment(_) => "SigningCommitment",
            ChannelState::AwaitingTxSignatures(_) => "AwaitingTxSignatures",
            ChannelState::AwaitingChannelReady(_) => "AwaitingChannelReady",
            ChannelState::ShuttingDown(_) => "ShuttingDown",
            ChannelState::Closed(_) => "Closed",
            ChannelState::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ChannelStateInfo {
    Structured(ChannelState),
    Simple(String),
}

impl ChannelStateInfo {
    pub fn is_ready(&self) -> bool {
        match self {
            ChannelStateInfo::Structured(ChannelState::ChannelReady) => true,
            ChannelStateInfo::Simple(s) => {
                s.eq_ignore_ascii_case("ChannelReady") || s.eq_ignore_ascii_case("Ready")
            }
            _ => false,
        }
    }

    pub fn is_stale(&self) -> bool {
        match self {
            ChannelStateInfo::Structured(ChannelState::Stale) => true,
            ChannelStateInfo::Simple(s) => s.eq_ignore_ascii_case("Stale"),
            _ => false,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ChannelStateInfo::Structured(st) => st.as_str(),
            ChannelStateInfo::Simple(s) => s.as_str(),
        }
    }
}

impl Default for ChannelStateInfo {
    fn default() -> Self {
        ChannelStateInfo::Simple("Unknown".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub state: ChannelStateInfo,
    #[serde(default)]
    pub peer_id: Option<String>,
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub local_balance: Option<String>,
    #[serde(default)]
    pub remote_balance: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListChannelsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_closed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_pending: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListChannelsResult {
    #[serde(default)]
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentStatus {
    Created,
    Inflight,
    Success,
    Failed,
}

impl PaymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentStatus::Created => "Created",
            PaymentStatus::Inflight => "Inflight",
            PaymentStatus::Success => "Success",
            PaymentStatus::Failed => "Failed",
        }
    }
}

pub mod opt_hex_or_int_u64 {
    use super::*;

    pub fn serialize<S>(val: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match val {
            Some(n) => serializer.serialize_str(&format!("0x{:x}", n)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<serde_json::Value>::deserialize(deserializer)?;
        match opt {
            Some(serde_json::Value::Number(n)) => n
                .as_u64()
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom("invalid integer for u64")),
            Some(serde_json::Value::String(s)) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16)
                        .map(Some)
                        .map_err(serde::de::Error::custom)
                } else {
                    trimmed
                        .parse::<u64>()
                        .map(Some)
                        .map_err(serde::de::Error::custom)
                }
            }
            Some(serde_json::Value::Null) | None => Ok(None),
            _ => Err(serde::de::Error::custom(
                "expected integer, hex string, or null for u64",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PaymentInfo {
    pub payment_hash: String,
    #[serde(default)]
    pub status: Option<PaymentStatus>,
    #[serde(default, with = "opt_hex_or_int_u64")]
    pub created_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListPaymentsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PaymentStatus>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_hex_or_int_u64"
    )]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListPaymentsResult {
    #[serde(default)]
    pub payments: Vec<PaymentInfo>,
    #[serde(default)]
    pub last_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_info_hex_and_int_created_at() {
        let json_hex =
            r#"{"payment_hash":"0xabc","status":"Success","created_at":"0x191e4f29f40"}"#;
        let payment: PaymentInfo = serde_json::from_str(json_hex).unwrap();
        assert_eq!(payment.payment_hash, "0xabc");
        assert_eq!(payment.status, Some(PaymentStatus::Success));
        assert_eq!(payment.created_at, Some(1726122991424));

        let json_int = r#"{"payment_hash":"0xabc","status":"Success","created_at":1726122991424}"#;
        let payment_int: PaymentInfo = serde_json::from_str(json_int).unwrap();
        assert_eq!(payment_int.created_at, Some(1726122991424));

        let json_null = r#"{"payment_hash":"0xabc","status":null,"created_at":null}"#;
        let payment_null: PaymentInfo = serde_json::from_str(json_null).unwrap();
        assert_eq!(payment_null.created_at, None);
    }

    #[test]
    fn test_list_payments_params_hex_serialization() {
        let params = ListPaymentsParams {
            status: Some(PaymentStatus::Success),
            limit: Some(16),
            after: Some("cursor_123".to_string()),
        };
        let val = serde_json::to_value(&params).unwrap();
        assert_eq!(val["limit"], "0x10");
        assert_eq!(val["status"], "Success");
        assert_eq!(val["after"], "cursor_123");
    }

    #[test]
    fn test_channel_state_adjacently_tagged() {
        let json = r#"{"state_name":"ChannelReady"}"#;
        let state: ChannelState = serde_json::from_str(json).unwrap();
        assert_eq!(state, ChannelState::ChannelReady);

        let json_stale = r#"{"state_name":"Stale"}"#;
        let state_stale: ChannelState = serde_json::from_str(json_stale).unwrap();
        assert_eq!(state_stale, ChannelState::Stale);
    }
}
