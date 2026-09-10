//! The request a site sends and the reply it receives.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// `{"plugin":"pfx","name":"load_key","arguments":["/Volumes/","DSKEYS","K","cn=..."]}`
/// `plugin` may be absent or empty, which means the unnamed "main" plugin.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub arguments: Vec<String>,
}

impl Request {
    pub fn arg(&self, index: usize) -> &str {
        self.arguments.get(index).map(String::as_str).unwrap_or("")
    }
}

/// A reply. `success` and `status` always appear; everything else is merged in
/// from the function's own payload, which is how the original's per-function
/// response classes serialize.
#[derive(Clone, Debug, Serialize)]
pub struct Response {
    pub success: bool,
    pub status: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub payload: Map<String, Value>,
    /// The `apidoc` reply is a bare JSON array, unlike every other reply; see
    /// `raw` below. Never set outside that one case.
    #[serde(skip)]
    pub raw: Option<Value>,
}

impl Response {
    pub fn failure(status: i32, reason: String) -> Self {
        Response { success: false, status, reason: Some(reason), payload: Map::new(), raw: None }
    }

    pub fn success() -> Self {
        Response { success: true, status: 1, reason: None, payload: Map::new(), raw: None }
    }

    /// The `apidoc` reply is a bare JSON array, unlike every other reply.
    pub fn raw(value: Value) -> Self {
        Response { success: true, status: 1, reason: None, payload: Map::new(), raw: Some(value) }
    }

    /// `{"success":true,"status":1,"message":"..."}` — the original's
    /// `JsonSuccessfulResponse(String)`.
    pub fn message(text: impl Into<String>) -> Self {
        Response::success().with("message", Value::String(text.into()))
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.payload.insert(key.to_string(), value);
        self
    }

    /// Serializes a payload struct and merges its fields at the top level.
    pub fn with_payload<T: Serialize>(mut self, payload: &T) -> crate::error::Result<Self> {
        let value = serde_json::to_value(payload)
            .map_err(|e| crate::error::RpcError::Runtime(e.to_string()))?;
        if let Value::Object(map) = value {
            for (k, v) in map {
                self.payload.insert(k, v);
            }
        }
        Ok(self)
    }

    pub fn to_json(&self) -> String {
        let fallback = || {
            r#"{"success":false,"status":-9999,"reason":"response serialization failed"}"#.to_string()
        };
        match &self.raw {
            Some(raw) => serde_json::to_string(raw).unwrap_or_else(|_| fallback()),
            None => serde_json::to_string(self).unwrap_or_else(|_| fallback()),
        }
    }
}
