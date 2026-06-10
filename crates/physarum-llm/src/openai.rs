use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

use crate::{
    client::{QueryFuture, TemplateFuture},
    prompt::{
        build_template_selection_prompt, build_user_prompt, STRATEGY_SCHEMA, SYSTEM_PROMPT,
        TEMPLATE_SELECTION_SYSTEM_PROMPT,
    },
    types::{
        DiscoveryQuery, PropagationMethodClass, PropagationStrategy, TemplateSelectionQuery,
        TemplateSelectionResponse,
    },
    LlmClient,
};

/// OpenAI-compatible LLM client.
///
/// Works with any backend that implements the `/v1/chat/completions` API:
/// OpenAI, Ollama, Groq, vLLM, LM Studio, etc.
///
/// Implements the two-turn LLM protocol:
///   Turn 1 — `select_templates`: compact catalog → selected IDs
///   Turn 2 — `query_propagation`: enriched findings → propagation strategy
pub struct OpenAiCompatibleClient {
    endpoint: String,
    model: String,
    api_key: String,
    timeout: Duration,
    allowed_methods: Vec<PropagationMethodClass>,
    http: Client,
    /// When true, log the full prompt and raw LLM response at DEBUG level.
    log_prompts: bool,
}

impl OpenAiCompatibleClient {
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        timeout_ms: u64,
        allowed_methods: Vec<PropagationMethodClass>,
        log_prompts: bool,
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
            log_prompts,
        })
    }

    async fn query_propagation_inner(&self, query: &DiscoveryQuery) -> Result<PropagationStrategy> {
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

        let url = self.completions_url();

        debug!(
            url = %url,
            model = %self.model,
            attempt = query.attempt_number,
            "sending DiscoveryQuery to LLM (Turn 2)"
        );
        if self.log_prompts {
            debug!(user_prompt = %user_prompt, "LLM Turn 2 request body");
        }

        let content = self.send_request(&request).await?;

        if self.log_prompts {
            debug!(raw_response = %content, "LLM Turn 2 raw response");
        }

        serde_json::from_str::<PropagationStrategy>(&content).map_err(|e| {
            if self.log_prompts {
                warn!(raw = %content, error = %e, "LLM response did not parse as PropagationStrategy");
                anyhow!("LLM response JSON parse error: {e} — raw: {content}")
            } else {
                warn!(error = %e, "LLM response did not parse as PropagationStrategy");
                anyhow!("LLM response JSON parse error: {e}")
            }
        })
    }

    async fn query_templates_inner(
        &self,
        query: &TemplateSelectionQuery,
    ) -> Result<TemplateSelectionResponse> {
        let query_json =
            serde_json::to_string(query).context("failed to serialize TemplateSelectionQuery")?;

        let user_prompt = build_template_selection_prompt(&query_json);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".into(),
                    content: TEMPLATE_SELECTION_SYSTEM_PROMPT.into(),
                },
                ChatMessage {
                    role: "user".into(),
                    content: user_prompt.clone(),
                },
            ],
            temperature: 0.3, // Slight randomness avoids repetition loops
            max_tokens: 512,  // Short: ≤15 IDs × ~10 tokens each; prevents infinite loops
        };

        let url = self.completions_url();

        debug!(
            url = %url,
            model = %self.model,
            catalog_size = query.available_templates.len(),
            "sending TemplateSelectionQuery to LLM (Turn 1)"
        );
        if self.log_prompts {
            debug!(user_prompt = %user_prompt, "LLM Turn 1 request body");
        }

        let content = self.send_request(&request).await?;

        if self.log_prompts {
            debug!(raw_response = %content, "LLM Turn 1 raw response");
        }

        serde_json::from_str::<TemplateSelectionResponse>(&content).map_err(|e| {
            if self.log_prompts {
                warn!(raw = %content, error = %e, "LLM response did not parse as TemplateSelectionResponse");
                anyhow!("LLM template-selection JSON parse error: {e} — raw: {content}")
            } else {
                warn!(error = %e, "LLM response did not parse as TemplateSelectionResponse");
                anyhow!("LLM template-selection JSON parse error: {e}")
            }
        })
    }

    fn completions_url(&self) -> String {
        format!(
            "{}/v1/chat/completions",
            self.endpoint.trim_end_matches('/')
        )
    }

    async fn send_request(&self, request: &ChatRequest) -> Result<String> {
        let resp = self
            .http
            .post(self.completions_url())
            .bearer_auth(&self.api_key)
            .json(request)
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

        chat_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("LLM returned empty choices"))
            .map(|c| c.message.content)
    }
}

impl LlmClient for OpenAiCompatibleClient {
    fn select_templates<'a>(&'a self, query: &'a TemplateSelectionQuery) -> TemplateFuture<'a> {
        Box::pin(self.query_templates_inner(query))
    }

    fn query_propagation<'a>(&'a self, query: &'a DiscoveryQuery) -> QueryFuture<'a> {
        Box::pin(self.query_propagation_inner(query))
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
