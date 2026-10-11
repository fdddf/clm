//! A profile's environment: what a launch sets and clears, the settings catalog, and how a
//! profile is printed without its secrets.

use std::path::Path;
use std::sync::OnceLock;

use indexmap::IndexMap;
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::checks::{
    HIDDEN, carries_credential_token, looks_like_credential, redact_base_url, redact_urls_in, redacted_secret_value,
};
use crate::secrets::resolve_secret;
use crate::tools;
use crate::types::{Profile, Tool};
use crate::util::{self, is_posix_env_name};

/// Variables clm owns; a profile's env map may not redefine them.
pub fn is_reserved_env_key(key: &str) -> bool {
    matches!(key.to_uppercase().as_str(), "CLAUDE_CONFIG_DIR" | "CODEX_HOME")
}

/// The variables Claude Code takes a credential from, or that switch on an auth flow. For an
/// API profile each comes from the profile or not at all.
pub const CREDENTIAL_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_CUSTOM_HEADERS",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
    "ANTHROPIC_IDENTITY_TOKEN",
    "ANTHROPIC_IDENTITY_TOKEN_FILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "CLAUDE_CODE_HOST_AUTH_ENV_VAR",
    "CLAUDE_CODE_HOST_CREDS_FILE",
    "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
    "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
    "CLAUDE_BG_AUTH_SNAPSHOT_PATH",
];

/// The variables that send Claude Code's traffic somewhere other than ANTHROPIC_BASE_URL.
pub const ROUTING_ENV_KEYS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_USE_MANTLE",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD",
    "ANTHROPIC_UNIX_SOCKET",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "CLAUDE_CODE_CUSTOM_OAUTH_URL",
];

pub fn is_credential_env_key(key: &str) -> bool {
    CREDENTIAL_ENV_KEYS.contains(&key)
}

/// A name that says its value is a secret - for redaction and the plain-text warning.
pub fn is_secret_env_name(key: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)(^|_)(TOKEN|SECRET|PASSPHRASE|API_KEY|ACCESS_KEY|HEADERS|CREDENTIALS?|PRIVATE_KEY|MASTER_KEY|SIGNING_KEY|ENCRYPTION_KEY|SESSION_KEY|LICENSE_KEY|STORAGE_KEY|APP_KEY|CONNECTION_STRING|PAT|PWD|COOKIES?)(_|$)|PASSWORD",
        )
        .unwrap()
    });
    is_credential_env_key(key) || re.is_match(key)
}

fn api_managed_env_keys() -> Vec<&'static str> {
    let mut keys = vec!["ANTHROPIC_BASE_URL"];
    keys.extend_from_slice(CREDENTIAL_ENV_KEYS);
    keys.extend_from_slice(ROUTING_ENV_KEYS);
    keys
}

/// Another name `key` would be the same variable as on a case-insensitive environment.
pub fn env_key_case_twin<'a>(key: &str, others: impl IntoIterator<Item = &'a String>, api: bool) -> Option<String> {
    let upper = key.to_uppercase();
    for other in others {
        if other != key && other.to_uppercase() == upper {
            return Some(other.clone());
        }
    }
    if api {
        return api_managed_env_keys().into_iter().find(|m| *m != key && *m == upper).map(String::from);
    }
    None
}

pub fn env_key_case_twin_error(key: &str, twin: &str) -> String {
    format!("'{key}' differs from {twin} only in case, and Windows treats the two as one variable. Did you mean {twin}?")
}

/// The env map to read and change: an empty one for a missing map, `null` or `[]`; None for
/// one that is not a map at all.
pub fn env_map_of(env: Option<&Value>) -> Option<Map<String, Value>> {
    match env {
        None | Some(Value::Null) => Some(Map::new()),
        Some(Value::Array(a)) if a.is_empty() => Some(Map::new()),
        Some(Value::Object(m)) => Some(m.clone()),
        _ => None,
    }
}

pub fn invalid_env_map_message(id: &str) -> String {
    format!(
        "the env map in ~/.clm/profiles.json is not a map of NAME: value, so none of it is applied - run 'clm config {id} --edit' and save it as one"
    )
}

pub fn non_string_env_keys(env: &Map<String, Value>) -> Vec<String> {
    env.iter().filter(|(_, v)| !v.is_string()).map(|(k, _)| k.clone()).collect()
}

pub fn non_string_env_value_message(id: &str, key: &str) -> String {
    format!(
        "{} in the env map is not a string in quotes, so it is not applied - run 'clm config {id} --edit' and quote its value",
        shown_env_name(key)
    )
}

pub fn shown_env_name(key: &str) -> String {
    if carries_credential_token(key) { HIDDEN.into() } else { key.into() }
}

/// A stored string as it may be printed: without control characters.
pub fn printable(value: &str) -> String {
    value.chars().filter(|c| !matches!(*c as u32, 0x00..=0x1f | 0x7f..=0x9f)).collect()
}

pub fn shown_label(label: Option<&str>) -> Option<String> {
    let shown = printable(label?);
    Some(if carries_credential_token(&shown) { HIDDEN.into() } else { shown })
}

/// A kind as printed: `unknown` for a stored one that is neither kind.
pub fn shown_kind(kind: Option<&Value>) -> Option<String> {
    match kind {
        None => None,
        Some(Value::String(k)) if k == "subscription" || k == "api" => Some(k.clone()),
        Some(_) => Some("unknown".into()),
    }
}

pub fn display_name(email: &str, label: Option<&str>) -> String {
    let label = printable(label.unwrap_or("")).trim().to_string();
    if !label.is_empty() && carries_credential_token(&label) {
        return HIDDEN.into();
    }
    if label.is_empty() { printable(email) } else { label }
}

pub fn profile_display_name(profile: &Profile) -> String {
    display_name(&profile.email, profile.label.as_deref())
}

/// The model a profile pins: its env map's ANTHROPIC_MODEL.
pub fn profile_model(profile: &Profile) -> Option<String> {
    if profile.tool() != Tool::Claude {
        return None;
    }
    let model = profile.env.as_ref()?.as_object()?.get("ANTHROPIC_MODEL")?.as_str()?;
    let model = printable(model);
    if model.trim().is_empty() {
        return None;
    }
    Some(if carries_credential_token(&model) { HIDDEN.into() } else { model })
}

/// What one run needs: variables to set, and variables that must be absent.
pub struct BuiltEnv {
    pub env: IndexMap<String, String>,
    pub unset: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn settings_env_overrides(env: Option<&Value>, names: &[&str]) -> Vec<String> {
    let Some(Value::Object(map)) = env else {
        return Vec::new();
    };
    let mut keys: Vec<String> = map.keys().filter(|k| names.contains(&k.to_uppercase().as_str())).cloned().collect();
    keys.sort();
    keys
}

fn settings_env_warnings(id: &str, config_dir: &Path) -> Vec<String> {
    let Some(settings) = util::read_json(&config_dir.join("settings.json")) else {
        return Vec::new();
    };
    settings_env_overrides(settings.get("env"), &api_managed_env_keys())
        .into_iter()
        .map(|key| {
            format!(
                "{id}: {} is set in the env block of settings.json, and Claude Code applies it over this profile - run 'clm doctor' for the fix",
                shown_env_name(&key)
            )
        })
        .collect()
}

/// Turns one profile into the environment a single tool run needs. Config dir first, then the
/// API block, then the free-form env map, so an explicit setting wins - except the config
/// variable itself, which would break profile isolation.
pub fn build_profile_env(id: &str, profile: &Profile) -> BuiltEnv {
    let tool = profile.tool();
    let mut env: IndexMap<String, String> = IndexMap::new();
    let mut warnings = Vec::new();

    let resolved_config = util::realpath(&profile.dir()).unwrap_or_else(|| profile.dir());
    let default_dir = tools::default_config_dir(tool);
    let resolved_default = util::realpath(&default_dir).unwrap_or(default_dir);
    if !profile.primary() && resolved_config != resolved_default {
        env.insert(tools::config_env_var(tool).into(), profile.config_dir.clone());
    }

    let api = if profile.is_api() { profile.api.as_ref() } else { None };
    if let Some(api) = api {
        env.insert("ANTHROPIC_BASE_URL".into(), api.base_url.clone());
        match resolve_secret(id, api.secret().as_ref()) {
            Ok(secret) => {
                let var = if api.auth_scheme == "bearer" { "ANTHROPIC_AUTH_TOKEN" } else { "ANTHROPIC_API_KEY" };
                env.insert(var.into(), secret);
            }
            Err(e) => warnings.push(format!("{id}: {e}")),
        }
        warnings.extend(settings_env_warnings(id, &profile.dir()));
    }

    let map = env_map_of(profile.env.as_ref());
    if map.is_none() {
        warnings.push(format!("{id}: {}", invalid_env_map_message(id)));
    }
    for (key, value) in map.unwrap_or_default() {
        if shown_env_name(&key) != key {
            warnings.push(format!(
                "{id}: ignoring a name shaped like an API key from the env map - remove it with 'clm config {id} --edit'"
            ));
            continue;
        }
        if !is_posix_env_name(&key) {
            warnings.push(format!("{id}: ignoring '{key}' from the env map - not a valid environment variable name"));
            continue;
        }
        if is_reserved_env_key(&key) {
            warnings.push(format!("{id}: ignoring {key} from the env map - clm sets it per profile"));
            continue;
        }
        if let Some(twin) = env_key_case_twin(&key, env.keys(), profile.is_api()) {
            warnings.push(format!(
                "{id}: ignoring '{key}' from the env map - it differs from {twin} only in case, and Windows treats the two as one variable"
            ));
            continue;
        }
        let Value::String(value) = value else {
            warnings.push(format!(
                "{id}: ignoring {key} from the env map - its value is not a string; run 'clm config {id} --edit' and quote it"
            ));
            continue;
        };
        env.insert(key, value);
    }

    let unset = if api.is_some() {
        CREDENTIAL_ENV_KEYS
            .iter()
            .chain(ROUTING_ENV_KEYS.iter())
            .filter(|k| !env.contains_key(**k))
            .map(|k| k.to_string())
            .collect()
    } else {
        Vec::new()
    };
    BuiltEnv { env, unset, warnings }
}

/// Every name an API profile's run must control: what it clears and what it sets.
pub fn controlled_env_keys(profile: &Profile, built: &BuiltEnv) -> Vec<String> {
    if !profile.is_api() || profile.api.is_none() {
        return Vec::new();
    }
    built.unset.iter().cloned().chain(built.env.keys().cloned()).collect()
}

// ─── The settings catalog ───────────────────────────────────────────

#[derive(Serialize, Clone, Copy)]
pub struct CatalogEntry {
    pub key: &'static str,
    pub label: &'static str,
    pub hint: &'static str,
    pub kind: &'static str,
    pub group: &'static str,
}

const fn entry(key: &'static str, label: &'static str, hint: &'static str, kind: &'static str, group: &'static str) -> CatalogEntry {
    CatalogEntry { key, label, hint, kind, group }
}

pub const CLAUDE_ENV_CATALOG: &[CatalogEntry] = &[
    entry("ANTHROPIC_MODEL", "Model", "Model id this profile sends", "string", "model"),
    entry("ANTHROPIC_DEFAULT_OPUS_MODEL", "Opus alias", "Model used when opus is selected", "string", "model"),
    entry("ANTHROPIC_DEFAULT_SONNET_MODEL", "Sonnet alias", "Model used when sonnet is selected", "string", "model"),
    entry("ANTHROPIC_DEFAULT_HAIKU_MODEL", "Haiku alias", "Model used for fast background calls", "string", "model"),
    entry("CLAUDE_CODE_SUBAGENT_MODEL", "Subagent model", "Model subagents run on", "string", "model"),
    entry(
        "CLAUDE_CODE_MAX_CONTEXT_TOKENS",
        "Context window",
        "Real window size; unknown models otherwise get a conservative guess and compact early",
        "number",
        "context",
    ),
    entry(
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
        "Auto-compact window",
        "Token budget auto-compact keeps a session within",
        "number",
        "context",
    ),
    entry(
        "DISABLE_AUTO_COMPACT",
        "Disable auto-compact",
        "Set to 1 to turn off automatic compaction of a full context window",
        "bool",
        "context",
    ),
    entry("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "Max output tokens", "Per-response output cap", "number", "limits"),
    entry("MAX_THINKING_TOKENS", "Max thinking tokens", "Extended thinking budget", "number", "limits"),
    entry(
        "API_TIMEOUT_MS",
        "Request timeout",
        "Milliseconds to wait for one request; raise for gateways that hold responses until complete",
        "number",
        "timeouts",
    ),
    entry(
        "CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS",
        "First-byte timeout",
        "Milliseconds to wait for the first streamed byte; raise for cold self-hosted servers",
        "number",
        "timeouts",
    ),
    entry("CLAUDE_STREAM_IDLE_TIMEOUT_MS", "Stream idle timeout", "Gap allowed between streamed chunks", "number", "timeouts"),
    entry("CLAUDE_CODE_MAX_RETRIES", "Max retries", "Retry attempts per request", "number", "timeouts"),
    entry(
        "DISABLE_PROMPT_CACHING",
        "Disable prompt caching",
        "Set to 1 to stop sending cache markers, for endpoints without cache support",
        "bool",
        "compat",
    ),
    entry(
        "DISABLE_INTERLEAVED_THINKING",
        "Disable interleaved thinking",
        "Set to 1 to stop requesting interleaved thinking, for endpoints that reject thinking blocks",
        "bool",
        "compat",
    ),
    entry(
        "CLAUDE_CODE_DISABLE_1M_CONTEXT",
        "Disable 1M context",
        "Set to 1 to never request the 1M-token context beta",
        "bool",
        "compat",
    ),
    entry("ANTHROPIC_BETAS", "Beta headers", "Comma-separated beta feature names", "string", "compat"),
    entry("ANTHROPIC_CUSTOM_HEADERS", "Custom headers", "Extra request headers, one per line", "string", "transport"),
    entry("CLAUDE_CODE_EXTRA_BODY", "Extra request body", "JSON object merged into each request body", "json", "transport"),
    entry("HTTPS_PROXY", "HTTPS proxy", "Proxy URL for outbound requests", "string", "transport"),
];

fn catalog_entry(key: &str) -> Option<&'static CatalogEntry> {
    CLAUDE_ENV_CATALOG.iter().find(|e| e.key == key)
}

/// Whether a setting's value is never printed: a secret's name, a json setting, or a name
/// shaped like a key.
pub fn hides_env_value(key: &str) -> bool {
    is_secret_env_name(key) || catalog_entry(key).is_some_and(|e| e.kind == "json") || shown_env_name(key) != key
}

const MISPLACED_KEY_VALUE: &str = "That setting's value is shaped like an API key, so it was not stored. A key never goes in the env map: an API profile takes it through --key or --key-from";

fn quoted_value(value: &str) -> String {
    if looks_like_credential(value) { ".".into() } else { format!(", got '{value}'") }
}

/// Checks one `KEY=VALUE` before it is stored. No refusal repeats a key-shaped value.
pub fn validate_env_entry(key: &str, value: &str, api: bool) -> Result<(), String> {
    if shown_env_name(key) != key {
        return Err("That setting's name is shaped like an API key. A key never goes in the env map: use --key or --key-from".into());
    }
    if !hides_env_value(key) && carries_credential_token(&redact_urls_in(&printable(value))) {
        return Err(MISPLACED_KEY_VALUE.into());
    }
    if !is_posix_env_name(key) {
        return Err(format!(
            "'{key}' is not a valid environment variable name - use letters, digits and underscores, starting with a letter or underscore"
        ));
    }
    if is_reserved_env_key(key) {
        return Err(format!("{key} is managed by clm and cannot be set on a profile"));
    }
    if api && key.eq_ignore_ascii_case("ANTHROPIC_BASE_URL") {
        return Err(format!("{key} is this profile's endpoint - set the endpoint with --base-url"));
    }
    let Some(entry) = catalog_entry(key) else {
        return Ok(());
    };
    match entry.kind {
        "number" => {
            let whole = value == "0" || (value.chars().next().is_some_and(|c| ('1'..='9').contains(&c)) && value.chars().all(|c| c.is_ascii_digit()));
            if !whole {
                return Err(format!("{key} expects a whole number{}", quoted_value(value)));
            }
        }
        "bool" if value != "0" && value != "1" => {
            return Err(format!("{key} expects 0 or 1{}", quoted_value(value)));
        }
        "json" => match serde_json::from_str::<Value>(value) {
            Err(_) => return Err(format!("{key} expects a JSON object")),
            Ok(Value::Object(_)) => {}
            Ok(other) => {
                let name = match other {
                    Value::Null => "null",
                    Value::Array(_) => "array",
                    Value::Bool(_) => "boolean",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Object(_) => "object",
                };
                return Err(format!("{key} expects a JSON object, got {name}"));
            }
        },
        _ => {}
    }
    Ok(())
}

/// A blank or key-shaped ANTHROPIC_MODEL, by any route that writes it.
pub fn check_model_entry(key: &str, value: &str, at_add: bool) -> anyhow::Result<()> {
    if key != "ANTHROPIC_MODEL" {
        return Ok(());
    }
    if carries_credential_token(value) {
        anyhow::bail!(
            "Give the model's id as your endpoint names it, such as z-ai/glm-5.3, and the key through {KEY_SOURCE_ROUTES}. This value for ANTHROPIC_MODEL looks like an API key, so it was not stored. If it is the model's id, pick it for one session with `claude --model` instead."
        );
    }
    if !value.trim().is_empty() {
        return Ok(());
    }
    if at_add {
        anyhow::bail!("A model id cannot be blank. To pin none, leave the model out.");
    }
    anyhow::bail!("A model id cannot be blank. To pin none, clear it with clm config <profile> --unset ANTHROPIC_MODEL.")
}

pub const KEY_SOURCE_ROUTES: &str = "the key source - the prompt or --key, or --key-from env:NAME";

// ─── Redaction ──────────────────────────────────────────────────────

fn hides_whole_value(key: &str, value: &Value) -> bool {
    match value {
        Value::String(s) => hides_env_value(key) || carries_credential_token(s) || carries_credential_token(&printable(s)),
        _ => true,
    }
}

/// The names whose value prints as `<hidden>`.
pub fn hidden_env_keys(env: Option<&Value>) -> Vec<String> {
    let Some(Value::Object(map)) = env else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for (k, v) in map {
        if hides_whole_value(k, v) {
            let name = shown_env_name(k);
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

pub fn redact_env(map: &Map<String, Value>) -> Map<String, Value> {
    map.iter()
        .map(|(k, v)| {
            let shown = if hides_whole_value(k, v) {
                HIDDEN.to_string()
            } else {
                redact_urls_in(&printable(v.as_str().unwrap_or("")))
            };
            (shown_env_name(k), Value::String(shown))
        })
        .collect()
}

/// A profile as every output path prints it: never a key, a command line, a secret setting or
/// a URL's userinfo and query; nothing a hand edit added.
pub fn redact_profile(profile: &Profile) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("tool".into(), json!(profile.tool));
    if let Some(kind) = shown_kind(profile.kind.as_ref()) {
        out.insert("kind".into(), json!(kind));
    }
    out.insert("configDir".into(), json!(profile.config_dir));
    out.insert("email".into(), json!(profile.email));
    if let Some(label) = shown_label(profile.label.as_deref()) {
        out.insert("label".into(), json!(label));
    }
    if let Some(org) = &profile.org_name {
        out.insert("orgName".into(), json!(org));
    }
    if let Some(p) = profile.is_primary {
        out.insert("isPrimary".into(), json!(p));
    }
    if let Some(m) = profile.merge_sessions {
        out.insert("mergeSessions".into(), json!(m));
    }
    if let Some(api) = &profile.api {
        out.insert(
            "api".into(),
            json!({
                "baseUrl": redact_base_url(&api.base_url),
                "authScheme": printable(&api.auth_scheme),
                "secret": redacted_secret_value(api.secret().as_ref()),
            }),
        );
    }
    if let Some(env) = &profile.env {
        out.insert(
            "env".into(),
            match env_map_of(Some(env)) {
                Some(map) => Value::Object(redact_env(&map)),
                None => json!(HIDDEN),
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_names() {
        assert!(is_secret_env_name("OTEL_EXPORTER_OTLP_HEADERS"));
        assert!(is_secret_env_name("PGPASSWORD"));
        assert!(is_secret_env_name("github_token"));
        assert!(!is_secret_env_name("CLAUDE_CODE_MAX_CONTEXT_TOKENS"));
        assert!(!is_secret_env_name("MAX_THINKING_TOKENS"));
    }

    #[test]
    fn entries() {
        assert!(validate_env_entry("API_TIMEOUT_MS", "600000", true).is_ok());
        assert!(validate_env_entry("API_TIMEOUT_MS", "6s", true).is_err());
        assert!(validate_env_entry("ANTHROPIC_BASE_URL", "http://x", true).is_err());
        assert!(validate_env_entry("CLAUDE_CONFIG_DIR", "/x", false).is_err());
        assert!(validate_env_entry("CLAUDE_CODE_EXTRA_BODY", "[1]", false).is_err());
    }
}
