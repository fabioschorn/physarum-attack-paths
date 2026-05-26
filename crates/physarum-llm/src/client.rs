use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::types::{DiscoveryQuery, PropagationStrategy};

/// Boxed future returned by `LlmClient::query_propagation`.
/// Using an explicit return type keeps the trait object-safe (dyn LlmClient)
/// without requiring a third-party async-trait crate.
pub type QueryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PropagationStrategy>> + Send + 'a>>;

/// The agnostic LLM contract.
///
/// Any backend (OpenAI, Ollama, Groq, vLLM, mock) implements this trait.
/// physarum-maze holds a `Box<dyn LlmClient>` and never knows the backend.
///
/// Phase 3 adds `OpenAiCompatibleClient` and `MockLlmClient`.
pub trait LlmClient: Send + Sync {
    /// Query the configured LLM backend for a propagation strategy.
    ///
    /// The caller is responsible for:
    /// - Populating `query.rejected_strategies` with all prior rejections.
    /// - Incrementing `query.attempt_number` before each call.
    /// - Enforcing the 6-attempt maximum before calling this method.
    fn query_propagation<'a>(&'a self, query: &'a DiscoveryQuery) -> QueryFuture<'a>;
}
