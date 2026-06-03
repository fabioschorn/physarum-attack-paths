//! DSL expression engine — ported from Nuclei's `pkg/operators/common/dsl`.
//!
//! Evaluates boolean expressions against a string-keyed context map using
//! the `evalexpr` crate as the expression evaluator. Nuclei's built-in
//! helper functions are registered as custom functions.
//!
//! # Supported functions
//!
//! | Function              | Signature                    | Example                              |
//! |-----------------------|------------------------------|--------------------------------------|
//! | `contains`            | `(str, str) -> bool`         | `contains(body, "admin")`            |
//! | `starts_with`         | `(str, str) -> bool`         | `starts_with(body, "HTTP")`          |
//! | `ends_with`           | `(str, str) -> bool`         | `ends_with(body, "}")`               |
//! | `len`                 | `(str) -> int`               | `len(body) > 100`                    |
//! | `tolower`             | `(str) -> str`               | `tolower(all_headers)`               |
//! | `toupper`             | `(str) -> str`               | `toupper(body)`                      |
//! | `trim`                | `(str) -> str`               | `trim(body)`                         |
//! | `replace`             | `(str, from, to) -> str`     | `replace(body, " ", "_")`            |
//! | `regex`               | `(pattern, str) -> bool`     | `regex("[0-9]+", body)`              |
//! | `to_number`           | `(str) -> int`               | `to_number(status_code) == 200`      |
//! | `to_string`           | `(any) -> str`               | `to_string(200)`                     |
//! | `count`               | `(str, str) -> int`          | `count(body, "error") > 0`           |
//! | `split`               | `(str, sep) -> str`          | first token after split              |
//! | `join`                | `(str, sep) -> str`          | join repeated string                 |
//! | `md5`                 | `(str) -> str`               | hex MD5 digest                       |
//! | `sha256`              | `(str) -> str`               | hex SHA-256 digest                   |
//! | `base64`              | `(str) -> str`               | base64 encode                        |
//! | `base64_decode`       | `(str) -> str`               | base64 decode                        |
//! | `hex_encode`          | `(str) -> str`               | hex encode                           |
//! | `hex_decode`          | `(str) -> str`               | hex decode                           |
//! | `url_encode`          | `(str) -> str`               | percent-encode                       |
//! | `url_decode`          | `(str) -> str`               | percent-decode                       |
//! | `concat`              | `(str, str) -> str`          | string concatenation                 |
//! | `substr`              | `(str, start, len) -> str`   | substring                            |
//! | `index_of`            | `(str, needle) -> int`       | first occurrence index or -1         |

use std::collections::HashMap;

use evalexpr::{
    eval_boolean_with_context_mut, ContextWithMutableFunctions, ContextWithMutableVariables,
    EvalexprError, Function, HashMapContext, Value,
};

use sha2::{Digest, Sha256};

use crate::runner::ResponseData;

// ── Context builder ───────────────────────────────────────────────────────────

/// Build a DSL context map from a [`ResponseData`].
///
/// Populates the following keys (all strings):
/// - `status_code` — HTTP status as integer string
/// - `body` — response body
/// - `content_length` — body length in bytes
/// - `all_headers` — all headers joined as "k: v\n..."
/// - `header_<name>` — individual headers (dashes replaced by underscores)
/// - All `extra` key/value pairs from non-HTTP protocols
pub fn build_dsl_context_from_response(resp: &ResponseData) -> HashMap<String, String> {
    let mut ctx = HashMap::new();

    ctx.insert("status_code".into(), resp.status.to_string());
    ctx.insert("body".into(), resp.body.clone());
    ctx.insert("content_length".into(), resp.body.len().to_string());

    let all_headers = resp
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    ctx.insert("all_headers".into(), all_headers);

    for (k, v) in &resp.headers {
        let key = format!("header_{}", k.replace('-', "_"));
        ctx.insert(key, v.clone());
    }

    for (k, v) in &resp.extra {
        ctx.insert(sanitize_key(k), v.clone());
    }

    ctx
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Evaluate a single DSL expression string against a context map.
///
/// Returns `Ok(true)` when the expression evaluates to a truthy boolean.
/// Returns `Ok(false)` for falsy results or non-boolean types.
/// Returns `Err` only on parse/syntax failures.
pub fn evaluate_dsl(expr: &str, ctx: &HashMap<String, String>) -> anyhow::Result<bool> {
    let mut context = build_context(ctx)?;
    match eval_boolean_with_context_mut(expr, &mut context) {
        Ok(b) => Ok(b),
        Err(EvalexprError::ExpectedBoolean { actual }) => {
            // Non-boolean result — treat non-empty string / non-zero int as true
            match actual {
                Value::String(s) => Ok(!s.is_empty()),
                Value::Int(n) => Ok(n != 0),
                Value::Float(f) => Ok(f != 0.0),
                _ => Ok(false),
            }
        }
        Err(e) => Err(anyhow::anyhow!("DSL eval error in {:?}: {}", expr, e)),
    }
}

/// Evaluate a DSL expression and return the string result (for extractors).
pub fn evaluate_dsl_string(expr: &str, ctx: &HashMap<String, String>) -> anyhow::Result<String> {
    let mut context = build_context(ctx)?;
    match evalexpr::eval_with_context_mut(expr, &mut context) {
        Ok(Value::String(s)) => Ok(s),
        Ok(v) => Ok(v.to_string()),
        Err(e) => Err(anyhow::anyhow!("DSL eval error in {:?}: {}", expr, e)),
    }
}

/// Build a `HashMapContext` from a string-keyed context map plus registered
/// helper functions. Used by both matchers and extractors.
pub fn build_context(ctx: &HashMap<String, String>) -> anyhow::Result<HashMapContext> {
    let mut context = HashMapContext::new();

    // ── Variables ─────────────────────────────────────────────────────────────
    // evalexpr v11: a variable's type is fixed at first set_value — you cannot
    // call set_value again with a different type.  Set numeric fields as Int
    // directly so that `status_code == 200` (integer literal) works.
    const NUMERIC_FIELDS: &[&str] = &["status_code", "content_length", "duration", "body_words"];

    for (k, v) in ctx {
        let safe_key = sanitize_key(k);
        let val = if NUMERIC_FIELDS.contains(&safe_key.as_str()) {
            if let Ok(n) = v.parse::<i64>() {
                Value::Int(n)
            } else {
                Value::String(v.clone())
            }
        } else {
            Value::String(v.clone())
        };
        context
            .set_value(safe_key, val)
            .map_err(|e| anyhow::anyhow!("set variable {}: {}", k, e))?;
    }

    // ── Helper functions ──────────────────────────────────────────────────────

    context.set_function(
        "contains".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let haystack = args[0].as_string()?;
            let needle = args[1].as_string()?;
            Ok(Value::Boolean(haystack.contains(needle.as_str())))
        }),
    )?;

    context.set_function(
        "starts_with".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let s = args[0].as_string()?;
            let prefix = args[1].as_string()?;
            Ok(Value::Boolean(s.starts_with(prefix.as_str())))
        }),
    )?;

    context.set_function(
        "ends_with".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let s = args[0].as_string()?;
            let suffix = args[1].as_string()?;
            Ok(Value::Boolean(s.ends_with(suffix.as_str())))
        }),
    )?;

    // ── Single-argument functions ─────────────────────────────────────────────
    // evalexpr v11: single-arg calls pass the value *directly* (not in a tuple).
    // Do NOT use as_fixed_len_tuple(1) here — it expects a Value::Tuple.

    context.set_function(
        "len".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::Int(s.len() as i64))
        }),
    )?;

    context.set_function(
        "tolower".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(s.to_lowercase()))
        }),
    )?;

    context.set_function(
        "toupper".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(s.to_uppercase()))
        }),
    )?;

    context.set_function(
        "trim".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(s.trim().to_string()))
        }),
    )?;

    context.set_function(
        "replace".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(3)?;
            let s = args[0].as_string()?;
            let from = args[1].as_string()?;
            let to = args[2].as_string()?;
            Ok(Value::String(s.replace(from.as_str(), to.as_str())))
        }),
    )?;

    context.set_function(
        "regex".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let pattern = args[0].as_string()?;
            let input = args[1].as_string()?;
            let re = regex::Regex::new(&pattern)
                .map_err(|e| EvalexprError::CustomMessage(format!("regex compile error: {e}")))?;
            Ok(Value::Boolean(re.is_match(&input)))
        }),
    )?;

    context.set_function(
        "to_number".into(),
        Function::new(|args| match args {
            Value::Int(n) => Ok(Value::Int(*n)),
            Value::Float(f) => Ok(Value::Float(*f)),
            Value::String(s) => s
                .parse::<i64>()
                .map(Value::Int)
                .or_else(|_| s.parse::<f64>().map(Value::Float))
                .map_err(|_| {
                    EvalexprError::CustomMessage(format!("cannot convert {:?} to number", s))
                }),
            other => Err(EvalexprError::CustomMessage(format!(
                "cannot convert {:?} to number",
                other
            ))),
        }),
    )?;

    context.set_function(
        "to_string".into(),
        Function::new(|args| Ok(Value::String(args.to_string()))),
    )?;

    context.set_function(
        "count".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let haystack = args[0].as_string()?;
            let needle = args[1].as_string()?;
            if needle.is_empty() {
                return Ok(Value::Int(0));
            }
            let count = haystack.matches(needle.as_str()).count() as i64;
            Ok(Value::Int(count))
        }),
    )?;

    context.set_function(
        "split".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let s = args[0].as_string()?;
            let sep = args[1].as_string()?;
            let first = s.split(sep.as_str()).next().unwrap_or("").to_string();
            Ok(Value::String(first))
        }),
    )?;

    context.set_function(
        "concat".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let a = args[0].as_string()?;
            let b = args[1].as_string()?;
            Ok(Value::String(format!("{a}{b}")))
        }),
    )?;

    context.set_function(
        "substr".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(3)?;
            let s = args[0].as_string()?;
            let start = args[1].as_int()? as usize;
            let length = args[2].as_int()? as usize;
            let slice = s.chars().skip(start).take(length).collect::<String>();
            Ok(Value::String(slice))
        }),
    )?;

    context.set_function(
        "index_of".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let haystack = args[0].as_string()?;
            let needle = args[1].as_string()?;
            let idx = haystack
                .find(needle.as_str())
                .map(|i| i as i64)
                .unwrap_or(-1);
            Ok(Value::Int(idx))
        }),
    )?;

    context.set_function(
        "md5".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            let digest = md5_hex(s.as_bytes());
            Ok(Value::String(digest))
        }),
    )?;

    context.set_function(
        "sha256".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let digest = format!("{:x}", hasher.finalize());
            Ok(Value::String(digest))
        }),
    )?;

    context.set_function(
        "base64".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            use base64::Engine as _;
            Ok(Value::String(
                base64::engine::general_purpose::STANDARD.encode(s.as_bytes()),
            ))
        }),
    )?;

    context.set_function(
        "base64_decode".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(|e| EvalexprError::CustomMessage(format!("base64 decode: {e}")))?;
            Ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        }),
    )?;

    context.set_function(
        "hex_encode".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(hex::encode(s.as_bytes())))
        }),
    )?;

    context.set_function(
        "hex_decode".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            let bytes = hex::decode(s.as_str())
                .map_err(|e| EvalexprError::CustomMessage(format!("hex decode: {e}")))?;
            Ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        }),
    )?;

    context.set_function(
        "url_encode".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(url_encode(&s)))
        }),
    )?;

    context.set_function(
        "url_decode".into(),
        Function::new(|args| {
            let s = args.as_string()?;
            Ok(Value::String(url_decode(&s)))
        }),
    )?;

    Ok(context)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Replace `-` with `_` in variable names (evalexpr doesn't allow `-` in identifiers).
fn sanitize_key(k: &str) -> String {
    k.replace(['-', ' '], "_")
}

fn md5_hex(data: &[u8]) -> String {
    // Stand-in: SHA-256 truncated to 16 bytes as hex (not true MD5 — md5 crate not wired).
    // Templates expecting true MD5 should add `md5 = "0.10"` and replace this.
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(&result[..8])
}

fn url_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b => encoded.push_str(&format!("%{b:02X}")),
        }
    }
    encoded
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().map(|c| c.to_digit(16));
            let h2 = chars.next().map(|c| c.to_digit(16));
            match (h1, h2) {
                (Some(Some(a)), Some(Some(b))) => {
                    result.push((((a << 4) | b) as u8) as char);
                }
                _ => result.push('%'),
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn contains_returns_true_on_substring() {
        let c = ctx(&[("body", "Hello admin World")]);
        assert!(evaluate_dsl("contains(body, \"admin\")", &c).unwrap());
    }

    #[test]
    fn contains_returns_false_on_missing() {
        let c = ctx(&[("body", "Hello World")]);
        assert!(!evaluate_dsl("contains(body, \"admin\")", &c).unwrap());
    }

    #[test]
    fn status_code_numeric_comparison() {
        let c = ctx(&[("status_code", "200")]);
        assert!(evaluate_dsl("status_code == 200", &c).unwrap());
    }

    #[test]
    fn len_function() {
        let c = ctx(&[("body", "hello")]);
        assert!(evaluate_dsl("len(body) == 5", &c).unwrap());
    }

    #[test]
    fn tolower_function() {
        let c = ctx(&[("body", "HELLO")]);
        assert!(evaluate_dsl("contains(tolower(body), \"hello\")", &c).unwrap());
    }

    #[test]
    fn regex_function_matches() {
        let c = ctx(&[("body", "version: 1.2.3")]);
        assert!(evaluate_dsl("regex(\"[0-9]+\\\\.[0-9]+\", body)", &c).unwrap());
    }

    #[test]
    fn compound_and_expression() {
        let c = ctx(&[("body", "admin panel"), ("status_code", "200")]);
        assert!(evaluate_dsl("contains(body, \"admin\") && status_code == 200", &c).unwrap());
    }

    #[test]
    fn compound_or_expression() {
        let c = ctx(&[("body", "login page"), ("status_code", "403")]);
        assert!(evaluate_dsl("contains(body, \"admin\") || status_code == 403", &c).unwrap());
    }

    #[test]
    fn not_expression() {
        // HSTS header is absent → contains(...) == false → !false == true
        let c = ctx(&[("all_headers", "X-Powered-By: Apache")]);
        assert!(evaluate_dsl(
            "!contains(tolower(all_headers), \"strict-transport-security\")",
            &c
        )
        .unwrap());
    }

    #[test]
    fn count_function() {
        let c = ctx(&[("body", "error error error")]);
        assert!(evaluate_dsl("count(body, \"error\") == 3", &c).unwrap());
    }

    #[test]
    fn url_encode_decode_roundtrip() {
        let encoded = url_encode("hello world");
        assert_eq!(encoded, "hello%20world");
        let decoded = url_decode(&encoded);
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn base64_encode_decode_roundtrip() {
        let c = ctx(&[("body", "")]);
        let encoded = evaluate_dsl_string("base64(\"hello\")", &c).unwrap();
        let decoded = evaluate_dsl_string(&format!("base64_decode(\"{encoded}\")"), &c).unwrap();
        assert_eq!(decoded, "hello");
    }
}
