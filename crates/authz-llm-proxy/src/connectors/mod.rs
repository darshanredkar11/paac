use async_trait::async_trait;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[async_trait]
pub trait DataConnector: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(&self, call: &ToolCall) -> Result<Value, String>;
}

pub struct MockDataConnector;

#[async_trait]
impl DataConnector for MockDataConnector {
    fn name(&self) -> &str {
        "mock"
    }

    async fn execute(&self, call: &ToolCall) -> Result<Value, String> {
        Ok(serde_json::json!({
            "tool": call.name,
            "id": call.id,
            "ok": true,
            "rows": [],
            "note": "mock connector — no production data touched"
        }))
    }
}

pub struct HttpDataConnector {
    pub base_url: String,
    pub client: reqwest::Client,
}

#[async_trait]
impl DataConnector for HttpDataConnector {
    fn name(&self) -> &str {
        "http"
    }

    async fn execute(&self, call: &ToolCall) -> Result<Value, String> {
        let url = format!("{}/tools/{}", self.base_url.trim_end_matches('/'), call.name);
        self.client
            .post(url)
            .json(&call.arguments)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }
}
