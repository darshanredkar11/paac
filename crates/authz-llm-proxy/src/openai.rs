use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<Value>,
    #[serde(default)]
    pub tool_calls: Option<Vec<ToolCallMsg>>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallMsg {
    pub id: String,
    #[serde(rename = "type", default = "default_fn_type")]
    pub type_: String,
    pub function: ToolFunction,
}

fn default_fn_type() -> String {
    "function".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFunction {
    pub name: String,
    pub arguments: String,
}

pub fn last_user_text(messages: &[ChatMessage]) -> Option<String> {
    for m in messages.iter().rev() {
        if m.role == "user" {
            return match &m.content {
                Some(Value::String(s)) => Some(s.clone()),
                Some(Value::Array(arr)) => {
                    let mut t = String::new();
                    for part in arr {
                        if let Some(s) = part.get("text").and_then(|v| v.as_str()) {
                            t.push_str(s);
                        }
                    }
                    if t.is_empty() {
                        None
                    } else {
                        Some(t)
                    }
                }
                _ => None,
            };
        }
    }
    None
}

#[derive(Debug, Deserialize)]
pub struct RetrieveRequest {
    pub collection: String,
    #[serde(default)]
    pub document_id: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub top_k: Option<usize>,
}
