use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::types::{
    DiscoveryQuery, PropagationStrategy, TemplateSelectionQuery, TemplateSelectionResponse,
};

/// Boxed future returned by `LlmClient::query_propagation`.
/// Using an explicit return type keeps the trait object-safe (dyn LlmClient)
/// without requiring a third-party async-trait crate.
pub type QueryFuture<'a> = Pin<Box<dyn Future<Output = Result<PropagationStrategy>> + Send + 'a>>;

/// Boxed future returned by `LlmClient::select_templates`.
pub type TemplateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TemplateSelectionResponse>> + Send + 'a>>;

/// The agnostic LLM contract.
///
/// Any backend (OpenAI, Ollama, Groq, vLLM, mock) implements this trait.
/// physarum-maze holds a `Box<dyn LlmClient>` and never knows the backend.
///
/// Two-turn interaction:
///   Turn 1 — `select_templates`: LLM picks which templates to run from a compact catalog.
///   Turn 2 — `query_propagation`: LLM sees template results and decides what to do.
pub trait LlmClient: Send + Sync {
    /// Turn 1 — Template selection before spore probes run.
    ///
    /// LLM receives target fingerprint + available template catalog.
    /// Returns the template IDs it wants to execute against the target.
    /// An empty `selected_ids` means run all available templates.
    fn select_templates<'a>(&'a self, query: &'a TemplateSelectionQuery) -> TemplateFuture<'a>;

    /// Turn 2 — Propagation strategy after spore results are available.
    ///
    /// The caller is responsible for:
    /// - Populating `query.rejected_strategies` with all prior rejections.
    /// - Incrementing `query.attempt_number` before each call.
    /// - Enforcing the 6-attempt maximum before calling this method.
    fn query_propagation<'a>(&'a self, query: &'a DiscoveryQuery) -> QueryFuture<'a>;
}
