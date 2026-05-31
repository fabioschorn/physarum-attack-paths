//! Built-in template catalog — 20 detection templates ported from Nuclei conventions.
//!
//! Templates are organised into five families:
//!   server    — identify the HTTP server software via `Server` header
//!   tech      — identify backend technology via `X-Powered-By` and similar headers
//!   status    — characterise the response by HTTP status code
//!   content   — analyse response body and content-type
//!   security  — flag absent security-hardening headers (low severity)
//!
//! All templates are validated at startup via `PatternTemplate::validate()`.

use crate::{
    extractor::{ExtractPart, ExtractorType, PatternExtractor},
    matcher::{MatchCondition, MatchPart, MatcherType, PatternMatcher},
    template::{HttpCheck, PatternProtocol, PatternTemplate, SeverityHint, TemplateInfo},
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn info(name: &str, description: &str, severity: SeverityHint, tags: &[&str]) -> TemplateInfo {
    TemplateInfo {
        name: name.into(),
        authors: vec!["physarum".into()],
        description: Some(description.into()),
        severity,
        tags: tags.iter().map(|s| s.to_string()).collect(),
        references: vec![],
    }
}

fn words_header(name: &str, words: &[&str], case_insensitive: bool) -> PatternMatcher {
    PatternMatcher {
        name: name.into(),
        matcher_type: MatcherType::Words {
            words: words.iter().map(|s| s.to_string()).collect(),
            case_insensitive,
            all_must_match: false,
        },
        part: MatchPart::Headers,
        negate: false,
    }
}

fn words_body(name: &str, words: &[&str], case_insensitive: bool) -> PatternMatcher {
    PatternMatcher {
        name: name.into(),
        matcher_type: MatcherType::Words {
            words: words.iter().map(|s| s.to_string()).collect(),
            case_insensitive,
            all_must_match: false,
        },
        part: MatchPart::Body,
        negate: false,
    }
}

fn status_matcher(name: &str, codes: &[u16]) -> PatternMatcher {
    PatternMatcher {
        name: name.into(),
        matcher_type: MatcherType::Status {
            codes: codes.to_vec(),
        },
        part: MatchPart::Status,
        negate: false,
    }
}

fn regex_extractor(name: &str, pattern: &str, group: usize, part: ExtractPart) -> PatternExtractor {
    PatternExtractor {
        name: name.into(),
        extractor_type: ExtractorType::Regex {
            pattern: pattern.into(),
            group,
        },
        part,
        internal: false,
    }
}

fn kval_extractor(name: &str, key: &str) -> PatternExtractor {
    PatternExtractor {
        name: name.into(),
        extractor_type: ExtractorType::Kval { key: key.into() },
        part: ExtractPart::Headers,
        internal: false,
    }
}

// ── server detection ──────────────────────────────────────────────────────────

fn nginx_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "nginx-server-detect".into(),
        info: info(
            "Nginx Server Detection",
            "Detects nginx via Server response header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("nginx-header", &["nginx"], true)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "server-version",
            r"nginx/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

fn apache_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "apache-server-detect".into(),
        info: info(
            "Apache Server Detection",
            "Detects Apache via Server response header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("apache-header", &["Apache"], false)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "server-version",
            r"Apache/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

fn iis_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "iis-server-detect".into(),
        info: info(
            "Microsoft IIS Detection",
            "Detects IIS via Server response header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("iis-header", &["Microsoft-IIS"], false)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "server-version",
            r"Microsoft-IIS/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

fn lighttpd_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "lighttpd-server-detect".into(),
        info: info(
            "lighttpd Detection",
            "Detects lighttpd via Server response header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("lighttpd-header", &["lighttpd"], true)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "server-version",
            r"lighttpd/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

fn caddy_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "caddy-server-detect".into(),
        info: info(
            "Caddy Server Detection",
            "Detects Caddy via Server response header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("caddy-header", &["Caddy"], false)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![kval_extractor("server-value", "server")],
        stop_at_first_match: true,
    }
}

fn openresty_server_detect() -> PatternTemplate {
    PatternTemplate {
        id: "openresty-server-detect".into(),
        info: info(
            "OpenResty Detection",
            "Detects OpenResty (nginx+LuaJIT) via Server header",
            SeverityHint::Info,
            &["detect", "tech", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("openresty-header", &["openresty"], true)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "server-version",
            r"openresty/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

// ── technology detection ──────────────────────────────────────────────────────

fn php_detect() -> PatternTemplate {
    PatternTemplate {
        id: "php-detect".into(),
        info: info(
            "PHP Detection",
            "Detects PHP via X-Powered-By response header",
            SeverityHint::Info,
            &["detect", "tech"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("php-header", &["PHP"], false)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "php-version",
            r"PHP/[\d.]+",
            0,
            ExtractPart::Headers,
        )],
        stop_at_first_match: true,
    }
}

fn asp_net_detect() -> PatternTemplate {
    PatternTemplate {
        id: "asp-net-detect".into(),
        info: info(
            "ASP.NET Detection",
            "Detects ASP.NET via X-Powered-By or X-AspNet-Version header",
            SeverityHint::Info,
            &["detect", "tech"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            words_header("powered-by", &["ASP.NET"], false),
            words_header("aspnet-version", &["X-AspNet-Version"], true),
        ],
        matchers_condition: MatchCondition::Or,
        extractors: vec![
            kval_extractor("x-powered-by", "x-powered-by"),
            kval_extractor("x-aspnet-version", "x-aspnet-version"),
        ],
        stop_at_first_match: false,
    }
}

fn node_express_detect() -> PatternTemplate {
    PatternTemplate {
        id: "node-express-detect".into(),
        info: info(
            "Node.js/Express Detection",
            "Detects Express.js via X-Powered-By header",
            SeverityHint::Info,
            &["detect", "tech"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header("express-header", &["Express"], false)],
        matchers_condition: MatchCondition::Or,
        extractors: vec![kval_extractor("x-powered-by", "x-powered-by")],
        stop_at_first_match: true,
    }
}

// ── http status ───────────────────────────────────────────────────────────────

fn http_status_ok() -> PatternTemplate {
    PatternTemplate {
        id: "http-status-ok".into(),
        info: info(
            "HTTP 200 OK",
            "Confirms target returns HTTP 200",
            SeverityHint::Info,
            &["detect", "http", "status"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![status_matcher("status-200", &[200])],
        matchers_condition: MatchCondition::Or,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

fn http_redirect() -> PatternTemplate {
    PatternTemplate {
        id: "http-redirect".into(),
        info: info(
            "HTTP Redirect Detected",
            "Detects HTTP 301/302 redirects and extracts Location",
            SeverityHint::Info,
            &["detect", "http", "status"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![status_matcher("redirect-status", &[301, 302, 307, 308])],
        matchers_condition: MatchCondition::Or,
        extractors: vec![kval_extractor("location", "location")],
        stop_at_first_match: false,
    }
}

fn http_auth_required() -> PatternTemplate {
    PatternTemplate {
        id: "http-auth-required".into(),
        info: info(
            "HTTP Authentication Required",
            "Target requires HTTP authentication (401)",
            SeverityHint::Medium,
            &["detect", "http", "auth"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![status_matcher("status-401", &[401])],
        matchers_condition: MatchCondition::Or,
        extractors: vec![kval_extractor("www-authenticate", "www-authenticate")],
        stop_at_first_match: false,
    }
}

fn http_forbidden() -> PatternTemplate {
    PatternTemplate {
        id: "http-forbidden".into(),
        info: info(
            "HTTP Forbidden",
            "Target returns HTTP 403 — access denied without auth challenge",
            SeverityHint::Low,
            &["detect", "http", "status"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![status_matcher("status-403", &[403])],
        matchers_condition: MatchCondition::Or,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

// ── content analysis ──────────────────────────────────────────────────────────

fn json_api_detect() -> PatternTemplate {
    PatternTemplate {
        id: "json-api-detect".into(),
        info: info(
            "JSON API Endpoint",
            "Detects endpoints returning application/json content-type",
            SeverityHint::Info,
            &["detect", "content", "api"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![words_header(
            "content-type-json",
            &["application/json"],
            true,
        )],
        matchers_condition: MatchCondition::Or,
        extractors: vec![kval_extractor("content-type", "content-type")],
        stop_at_first_match: false,
    }
}

fn http_page_title() -> PatternTemplate {
    PatternTemplate {
        id: "http-page-title".into(),
        info: info(
            "HTTP Page Title",
            "Extracts the HTML page <title> from HTTP 200 responses",
            SeverityHint::Info,
            &["detect", "content"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![status_matcher("status-200", &[200])],
        matchers_condition: MatchCondition::Or,
        extractors: vec![regex_extractor(
            "page-title",
            r"(?i)<title>([^<]{1,256})</title>",
            1,
            ExtractPart::Body,
        )],
        stop_at_first_match: false,
    }
}

fn server_version_exposed() -> PatternTemplate {
    PatternTemplate {
        id: "server-version-exposed".into(),
        info: info(
            "Server Version Exposed",
            "Server header discloses a specific version string — aids fingerprinting",
            SeverityHint::Low,
            &["detect", "tech", "server", "info-disclosure"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![PatternMatcher {
            name: "version-regex".into(),
            matcher_type: MatcherType::Regex {
                patterns: vec![
                    r"(?:nginx|Apache|lighttpd|Microsoft-IIS|Caddy|openresty)/[\d.]+".into(),
                ],
            },
            part: MatchPart::Headers,
            negate: false,
        }],
        matchers_condition: MatchCondition::Or,
        extractors: vec![
            regex_extractor(
                "version-string",
                r"[\w\-]+/[\d]+\.[\d]+(?:\.[\d]+)?",
                0,
                ExtractPart::Headers,
            ),
            kval_extractor("server-header", "server"),
        ],
        stop_at_first_match: false,
    }
}

// ── default pages ─────────────────────────────────────────────────────────────

fn default_nginx_page() -> PatternTemplate {
    PatternTemplate {
        id: "default-nginx-page".into(),
        info: info(
            "Default Nginx Welcome Page",
            "Target serves the default nginx welcome page — not yet configured",
            SeverityHint::Info,
            &["detect", "misconfiguration", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            status_matcher("status-200", &[200]),
            words_body("welcome-nginx", &["Welcome to nginx"], false),
        ],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: true,
    }
}

fn default_apache_page() -> PatternTemplate {
    PatternTemplate {
        id: "default-apache-page".into(),
        info: info(
            "Default Apache Welcome Page",
            "Target serves the default Apache test page — not yet configured",
            SeverityHint::Info,
            &["detect", "misconfiguration", "server"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            status_matcher("status-200", &[200]),
            words_body(
                "apache-default",
                &["Apache HTTP Server Test Page", "It works!"],
                false,
            ),
        ],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: true,
    }
}

// ── security header checks ────────────────────────────────────────────────────

fn missing_x_frame_options() -> PatternTemplate {
    PatternTemplate {
        id: "missing-x-frame-options".into(),
        info: info(
            "Missing X-Frame-Options Header",
            "Response lacks X-Frame-Options — target may be vulnerable to clickjacking",
            SeverityHint::Low,
            &["detect", "security-headers", "clickjacking"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            status_matcher("status-200", &[200]),
            PatternMatcher {
                name: "no-xfo".into(),
                matcher_type: MatcherType::Words {
                    words: vec!["x-frame-options".into()],
                    case_insensitive: true,
                    all_must_match: false,
                },
                part: MatchPart::Headers,
                negate: true,
            },
        ],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

fn missing_hsts() -> PatternTemplate {
    PatternTemplate {
        id: "missing-hsts".into(),
        info: info(
            "Missing Strict-Transport-Security Header",
            "Response lacks HSTS — HTTPS targets should send Strict-Transport-Security",
            SeverityHint::Low,
            &["detect", "security-headers", "hsts"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            status_matcher("status-200", &[200]),
            PatternMatcher {
                name: "no-hsts".into(),
                matcher_type: MatcherType::Words {
                    words: vec!["strict-transport-security".into()],
                    case_insensitive: true,
                    all_must_match: false,
                },
                part: MatchPart::Headers,
                negate: true,
            },
        ],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

fn missing_csp() -> PatternTemplate {
    PatternTemplate {
        id: "missing-csp".into(),
        info: info(
            "Missing Content-Security-Policy Header",
            "Response lacks a Content-Security-Policy header",
            SeverityHint::Low,
            &["detect", "security-headers", "csp"],
        ),
        protocol: PatternProtocol::Http,
        http_check: Some(HttpCheck::get("/")),
        matchers: vec![
            status_matcher("status-200", &[200]),
            PatternMatcher {
                name: "no-csp".into(),
                matcher_type: MatcherType::Words {
                    words: vec!["content-security-policy".into()],
                    case_insensitive: true,
                    all_must_match: false,
                },
                part: MatchPart::Headers,
                negate: true,
            },
        ],
        matchers_condition: MatchCondition::And,
        extractors: vec![],
        stop_at_first_match: false,
    }
}

// ── public API ────────────────────────────────────────────────────────────────

/// Returns all built-in templates. Panics at startup if any template contains
/// an invalid regex — fail-fast before touching the network.
pub fn all_templates() -> Vec<PatternTemplate> {
    let templates = vec![
        // server detection
        nginx_server_detect(),
        apache_server_detect(),
        iis_server_detect(),
        lighttpd_server_detect(),
        caddy_server_detect(),
        openresty_server_detect(),
        // technology detection
        php_detect(),
        asp_net_detect(),
        node_express_detect(),
        // http status
        http_status_ok(),
        http_redirect(),
        http_auth_required(),
        http_forbidden(),
        // content analysis
        json_api_detect(),
        http_page_title(),
        server_version_exposed(),
        // default pages
        default_nginx_page(),
        default_apache_page(),
        // security headers
        missing_x_frame_options(),
        missing_hsts(),
        missing_csp(),
    ];

    for t in &templates {
        t.validate()
            .unwrap_or_else(|e| panic!("built-in template '{}' is invalid: {e}", t.id));
    }

    templates
}
