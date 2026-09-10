use super::types::*;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct FnnRpcClient {
    url: String,
    auth_token: Option<String>,
    client: reqwest::Client,
    request_id: std::sync::Arc<AtomicU64>,
}

impl FnnRpcClient {
    pub fn new(url: impl Into<String>, auth_token: Option<String>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(ref token) = auth_token {
            let mut auth_val = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
                .context("Invalid characters in auth token")?;
            auth_val.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_val);
        }

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to construct HTTP client")?;

        Ok(Self { url: url.into(), auth_token, client, request_id: Arc::new(AtomicU64::new(1)) })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn has_auth(&self) -> bool {
        self.auth_token.is_some()
    }

    async fn call_rpc<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest::new(id, method, params);

        let resp = self
            .client
            .post(&self.url)
            .json(&req)
            .send()
            .await
            .with_context(|| format!("Failed to connect to FNN RPC at {}", self.url))?;

        if !resp.status().is_success() {
            bail!("FNN RPC endpoint returned HTTP status {}", resp.status().as_u16());
        }

        let rpc_res: JsonRpcResponse<R> =
            resp.json().await.context("Failed to parse JSON-RPC response from FNN")?;

        if let Some(err) = rpc_res.error {
            bail!("FNN RPC method '{}' error: {}", method, err);
        }

        rpc_res.result.ok_or_else(|| anyhow!("RPC response for '{}' contained null result", method))
    }

    pub async fn node_info(&self) -> Result<NodeInfoResult> {
        self.call_rpc("node_info", ()).await
    }

    pub async fn list_channels(
        &self,
        params: Option<ListChannelsParams>,
    ) -> Result<ListChannelsResult> {
        let params = params.unwrap_or_default();
        self.call_rpc("list_channels", (params,)).await
    }

    pub async fn list_payments(
        &self,
        params: Option<ListPaymentsParams>,
    ) -> Result<ListPaymentsResult> {
        let params = params.unwrap_or_default();
        self.call_rpc("list_payments", (params,)).await
    }

    /// Automatically paginates through `list_payments` using `last_cursor` until
    /// all payments are accumulated or `max_limit` is reached.
    pub async fn list_all_payments(
        &self,
        status: Option<PaymentStatus>,
        max_limit: Option<usize>,
    ) -> Result<Vec<PaymentInfo>> {
        let mut all_payments = Vec::new();
        let mut cursor: Option<String> = None;
        let batch_size = 50u64;

        loop {
            let params =
                ListPaymentsParams { status, limit: Some(batch_size), after: cursor.clone() };

            let res = self.list_payments(Some(params)).await?;
            if res.payments.is_empty() {
                break;
            }

            let count = res.payments.len();
            all_payments.extend(res.payments);

            if let Some(max) = max_limit
                && all_payments.len() >= max
            {
                all_payments.truncate(max);
                break;
            }

            match res.last_cursor {
                Some(next_cursor) if !next_cursor.is_empty() => {
                    if cursor.as_ref() == Some(&next_cursor) {
                        // Avoid infinite loop if cursor repeats
                        break;
                    }
                    cursor = Some(next_cursor);
                }
                _ => break,
            }

            if (count as u64) < batch_size {
                break;
            }
        }

        Ok(all_payments)
    }

    /// Triggers FNN's admin backup RPC. FNN v0.9.x returns `{"jsonrpc":"2.0","result":null,"id":1}`
    /// upon successful initiation, which is treated as success.
    pub async fn trigger_backup(&self) -> Result<()> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let req = JsonRpcRequest::new(id, "backup", ());

        let resp =
            self.client.post(&self.url).json(&req).send().await.with_context(|| {
                format!("Failed to send backup request to FNN RPC at {}", self.url)
            })?;

        if !resp.status().is_success() {
            bail!("FNN RPC endpoint returned HTTP status {}", resp.status().as_u16());
        }

        let json_val: serde_json::Value =
            resp.json().await.context("Failed to parse JSON-RPC response from FNN backup call")?;

        if let Some(err) = json_val.get("error")
            && !err.is_null()
        {
            bail!("FNN backup RPC error: {}", err);
        }

        Ok(())
    }
}
