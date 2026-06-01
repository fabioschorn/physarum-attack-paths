use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

use crate::{
    client::QueryFuture,
    prompt::{build_user_prompt, STRATEGY_SCHEMA, SYSTEM_PROMPT},
    types::{DiscoveryQuery, PropagationMethodClass, PropagationStrategy},
    LlmClient,
};

/// OpenAI-compatible LLM client.
///
/// Works with any backend that implements the `/v1/chat/completions` API:
/// OpenAI, Ollama, Groq, vLLM, LM Studio, etc.
///
/// `allowed_methods` mirrors the `PolicyGate` configuration — injected into
/// every prompt so the LLM only proposes methods the policy will accept.
///
/// The API key is injected at runtime from `$LLM_API_KEY` — never stored
/// in lineage or config files.
pub struct OpenAiCompatibleClient {
    endpoint: String,
    model: String,
    api_key: String,
    timeout: Duration,
    allowed_methods: Vec<PropagationMethodClass>,
    http: Client,
}

impl OpenAiCompatibleClient {
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout_ms: u64,
        allowed_methods: Vec<PropagationMethodClass>,
    ) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self {
            endpoint: endpoint.into(),
            model: model.into(),
            api_key: api_key.into(),
            timeout: Duration::from_millis(timeout_ms),
            allowed_methods,
            http,
        })
    }

    async fn query(&self, query: &DiscoveryQuery) -> Result<PropagationStrategy> {
        let query_json =
            serde_json::to_string(query).context("failed to serialize DiscoveryQuery")?;

        let user_prompt = build_user_prompt(&query_json, &self.allowed_methods, STRATEGY_SCHEMA);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: SYSTEM_PROMPT.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user_prompt.clone(),
                },
            ],
            temperature: 0.2,
            max_tokens: 1024,
        };

        let url = format!(
            "{}/v1/chat/completions",
            self.endpoint.trim_end_matches('/')
        );

        debug!(
            url = %url,
            model = %self.model,
            attempt = query.attempt_number,
            "sending DiscoveryQuery to LLM"
        );
        debug!(user_prompt = %user_prompt, "LLM request body");

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await
            .context("LLM request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("LLM endpoint returned {status}: {body}"));
        }

        let chat_resp: ChatResponse = resp
            .json()
            .await
            .context("failed to deserialise LLM response")?;

        let content = chat_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("LLM returned empty choices"))?
            .message
            .content;

        debug!(raw_response = %content, "LLM raw response");
        let strategy: PropagationStrategy = serde_json::from_str(&content).map_err(|e| {
            warn!(raw = %content, error = %e, "LLM response did not parse as PropagationStrategy");
            anyhow!("LLM response JSON parse error: {e} — raw: {content}")
        })?;

        Ok(strategy)
    }
}

impl LlmClient for OpenAiCompatibleClient {
    fn query_propagation<'a>(&'a self, query: &'a DiscoveryQuery) -> QueryFuture<'a> {
        Box::pin(self.query(query))
    }
}

// ── OpenAI wire types ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}
