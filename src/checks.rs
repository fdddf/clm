//! What a key looks like, what a base URL may carry, and how each is printed.

use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use crate::types::SecretSource;
use crate::util::is_posix_env_name;

pub const HIDDEN: &str = "<hidden>";

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

fn mixes_case(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().any(|c| c.is_ascii_uppercase())
}

/// The runs of `length` or more ASCII letters and digits in `value`.
fn runs(value: &str, length: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in value.char_indices() {
        if c.is_ascii_alphanumeric() {
            start.get_or_insert(i);
        } else if let Some(s) = start.take()
            && i - s >= length {
                out.push(&value[s..i]);
            }
    }
    if let Some(s) = start
        && value.len() - s >= length {
            out.push(&value[s..]);
        }
    out
}

fn looks_random(run: &str) -> bool {
    let has_lower = run.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = run.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = run.chars().any(|c| c.is_ascii_digit());
    if !(has_lower && has_upper && has_digit) {
        return false;
    }
    let chars: Vec<char> = run.chars().collect();
    let boundaries = chars.windows(2).filter(|w| w[0].is_ascii_digit() != w[1].is_ascii_digit()).count();
    boundaries >= 3
}

fn looks_url_safe_random(body: &str) -> bool {
    if body.chars().count() < 20 || !mixes_case(body) {
        return false;
    }
    static LOWER: OnceLock<Regex> = OnceLock::new();
    let lowercase: Vec<&str> = re(&LOWER, "[a-z]+").find_iter(body).map(|m| m.as_str()).collect();
    let total: usize = lowercase.iter().map(|s| s.len()).sum();
    let shuffled = total < 3 * lowercase.len();
    let pieces: Vec<&str> = body.split(['-', '_']).collect();
    let limit = (3f64).max(body.chars().count() as f64 / 6.0);
    if pieces.len() as f64 > limit {
        return shuffled && pieces.iter().any(|p| p.chars().count() >= 6);
    }
    shuffled || body.chars().any(|c| c.is_ascii_digit())
}

/// Whether `value` holds something shaped like an API key: a vendor prefix, a prefixed token
/// with mixed case, an `sk-` body that is random-looking, or a long random-looking run.
pub fn carries_credential_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    static VENDOR: OnceLock<Regex> = OnceLock::new();
    if re(&VENDOR, r"sk-(?:ant|or|proj)-[A-Za-z0-9_-]{16}").is_match(value) {
        return true;
    }
    static PREFIXED: OnceLock<Vec<Regex>> = OnceLock::new();
    let prefixed = PREFIXED.get_or_init(|| {
        [
            r"hf_([A-Za-z]{30,})",
            r"api_org_([A-Za-z]{30,})",
            r"AIza([A-Za-z0-9_-]{35})",
            r"gh[pousr]_([A-Za-z0-9]{36})",
            r"r8_([A-Za-z0-9]{30,})",
            r"pplx-([A-Za-z0-9]{40,})",
        ]
        .iter()
        .map(|p| Regex::new(p).unwrap())
        .collect()
    });
    for regex in prefixed {
        for caps in regex.captures_iter(value) {
            if mixes_case(caps.get(1).map(|m| m.as_str()).unwrap_or("")) {
                return true;
            }
        }
    }
    // fw_ keys, unless a letter comes right before the prefix.
    static FW: OnceLock<Regex> = OnceLock::new();
    for caps in re(&FW, r"fw_([A-Za-z0-9]{20,})").captures_iter(value) {
        let start = caps.get(0).unwrap().start();
        let preceded = value[..start].chars().last().is_some_and(|c| c.is_ascii_alphabetic());
        if !preceded && mixes_case(&caps[1]) {
            return true;
        }
    }
    static SK: OnceLock<Regex> = OnceLock::new();
    for caps in re(&SK, r"sk[-_]([A-Za-z0-9_-]+)").captures_iter(value) {
        let body = &caps[1];
        if runs(body, 16)
            .iter()
            .any(|r| r.chars().any(|c| c.is_ascii_alphabetic()) && r.chars().any(|c| c.is_ascii_digit()))
        {
            return true;
        }
        if looks_url_safe_random(body) {
            return true;
        }
    }
    runs(value, 32).into_iter().any(looks_random)
}

const MAX_NAME_LENGTH: usize = 64;

/// A profile name that is how an API key is spelled: `sk-…`, or longer than any name.
pub fn looks_like_credential(value: &str) -> bool {
    value.to_lowercase().starts_with("sk-") || value.chars().count() > MAX_NAME_LENGTH
}

pub const CREDENTIAL_AS_NAME_ERROR: &str = "That looks like an API key, not a profile name - a profile name is at most 64 characters and never starts with 'sk-'. A key is never an argument, because `ps` shows every process's arguments to every user on the machine: pipe it in (printf %s \"$KEY\" | clm add <profile> --api …) or point at it with --key-from env:NAME.";

// ─── Base URLs ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BaseUrlProblem {
    Empty,
    KeyShaped,
    Unparseable,
    Scheme(Option<String>),
    Credentials,
    KeyParameter(String),
}

fn is_credential_parameter(name: &str) -> bool {
    let normalized = name.to_lowercase().replace('-', "_");
    const NAMES: [&str; 10] =
        ["api_key", "apikey", "key", "token", "access_token", "secret", "password", "sig", "signature", "subscription_key"];
    if NAMES.contains(&normalized.as_str()) {
        return true;
    }
    static WORD: OnceLock<Regex> = OnceLock::new();
    re(&WORD, r"(^|_)(key|token|secret|password|passwd|sig|signature|auth|credential)s?(_|$)").is_match(&normalized)
}

pub fn check_base_url(base_url: &str) -> Result<Url, BaseUrlProblem> {
    if base_url.trim().is_empty() {
        return Err(BaseUrlProblem::Empty);
    }
    if carries_credential_token(base_url) {
        return Err(BaseUrlProblem::KeyShaped);
    }
    let url = Url::parse(base_url.trim()).map_err(|_| BaseUrlProblem::Unparseable)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        let first = base_url.trim().split(':').next().unwrap_or("");
        if looks_like_credential(first) {
            return Err(BaseUrlProblem::KeyShaped);
        }
        static SCHEME: OnceLock<Regex> = OnceLock::new();
        let scheme = url.scheme().to_string();
        let ok = re(&SCHEME, r"^[a-z][a-z0-9+.-]{0,9}$").is_match(&scheme);
        return Err(BaseUrlProblem::Scheme(ok.then_some(scheme)));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(BaseUrlProblem::Credentials);
    }
    for (name, _) in url.query_pairs() {
        if is_credential_parameter(&name) {
            return Err(BaseUrlProblem::KeyParameter(name.into_owned()));
        }
    }
    Ok(url)
}

/// `url.host` in the WHATWG sense: the host, and the port when it is not the default.
pub fn url_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

pub fn url_hostname(url: &Url) -> String {
    url.host_str().unwrap_or("").to_string()
}

pub fn is_anthropic_host(hostname: &str) -> bool {
    let h = hostname.to_lowercase();
    h == "anthropic.com" || h.ends_with(".anthropic.com")
}

pub fn is_loopback_host(hostname: &str) -> bool {
    static LOOP: OnceLock<Regex> = OnceLock::new();
    hostname == "localhost" || hostname == "[::1]" || re(&LOOP, r"^127\.\d+\.\d+\.\d+$").is_match(hostname)
}

pub fn sends_key_in_clear(url: &Url) -> bool {
    url.scheme() == "http" && !is_loopback_host(&url_hostname(url))
}

pub fn origin_of(base_url: &str) -> Option<String> {
    check_base_url(base_url).ok().map(|u| u.origin().ascii_serialization())
}

fn without_url_secrets(url: &Url, original: &str) -> String {
    let userinfo = !url.username().is_empty() || url.password().is_some();
    let search = url.query().is_some_and(|q| !q.is_empty());
    let hash = url.fragment().is_some_and(|f| !f.is_empty());
    if !userinfo && !search && !hash {
        return original.to_string();
    }
    let host = url_host(url);
    let authority = if host.is_empty() {
        String::new()
    } else {
        format!("//{}{host}", if userinfo { format!("{HIDDEN}@") } else { String::new() })
    };
    format!(
        "{}:{authority}{}{}{}",
        url.scheme(),
        url.path(),
        if search { format!("?{HIDDEN}") } else { String::new() },
        if hash { format!("#{HIDDEN}") } else { String::new() }
    )
}

/// Replaces scheme-less `user:pass@` at the start of each line. True when one was found.
fn replace_bare_userinfo(value: &str) -> (String, bool) {
    static SCHEME: OnceLock<Regex> = OnceLock::new();
    let scheme = re(&SCHEME, r"(?i)^[a-z][a-z0-9+.-]*://");
    let mut found = false;
    let lines: Vec<String> = value
        .split('\n')
        .map(|line| {
            let indent_len = line.len() - line.trim_start().len();
            let (indent, rest) = line.split_at(indent_len);
            let body = rest.strip_prefix("//").unwrap_or(rest);
            if scheme.is_match(body) {
                return line.to_string();
            }
            // `[^\s@/]*:[^\s]*@`, greedy: up to the last `@` before whitespace.
            let token_end = body.find(char::is_whitespace).unwrap_or(body.len());
            let token = &body[..token_end];
            let first_colon = token.find(':');
            let bad_before = |end: usize| token[..end].contains(['@', '/']);
            match (first_colon, token.rfind('@')) {
                (Some(c), Some(at)) if c < at && !bad_before(c) => {
                    found = true;
                    format!("{indent}{HIDDEN}@{}", &body[at + 1..])
                }
                _ => line.to_string(),
            }
        })
        .collect();
    (lines.join("\n"), found)
}

pub fn has_bare_userinfo(base_url: &str) -> bool {
    replace_bare_userinfo(base_url).1
}

/// A base URL as it may be printed: userinfo, query and fragment hidden, or the whole URL
/// when it does not parse or carries something shaped like a key.
pub fn redact_base_url(base_url: &str) -> String {
    if base_url.trim().is_empty() {
        return base_url.to_string();
    }
    if carries_credential_token(base_url) {
        return HIDDEN.into();
    }
    let Ok(url) = Url::parse(base_url.trim()) else {
        return HIDDEN.into();
    };
    if url.host_str().is_some_and(|h| !h.is_empty()) {
        return without_url_secrets(&url, base_url);
    }
    let (bare, found) = replace_bare_userinfo(base_url);
    if !found {
        return without_url_secrets(&url, base_url);
    }
    static Q: OnceLock<Regex> = OnceLock::new();
    static F: OnceLock<Regex> = OnceLock::new();
    let bare = re(&Q, r"\?[^#]*").replace(&bare, format!("?{HIDDEN}").as_str()).into_owned();
    re(&F, r"(?s)#.*$").replace(&bare, format!("#{HIDDEN}").as_str()).into_owned()
}

/// Every URL in a value with its userinfo, query and fragment hidden.
pub fn redact_urls_in(value: &str) -> String {
    let mut shown = value.to_string();
    if let Ok(url) = Url::parse(value.trim())
        && url.host_str().is_some_and(|h| !h.is_empty()) {
            shown = without_url_secrets(&url, value);
        }
    static EMBEDDED: OnceLock<Regex> = OnceLock::new();
    let shown = re(&EMBEDDED, r"(?i)([a-z][a-z0-9+.-]*://)[^\s]*@")
        .replace_all(&shown, format!("${{1}}{HIDDEN}@").as_str())
        .into_owned();
    replace_bare_userinfo(&shown).0
}

// ─── Key sources ────────────────────────────────────────────────────

/// A key source as printed: never a command line, and never an env name shaped like a key.
pub fn describe_secret_source(secret: Option<&SecretSource>) -> String {
    match secret {
        Some(SecretSource::Keychain) => "keychain".into(),
        Some(SecretSource::Env(name)) => {
            let shown = if is_posix_env_name(name) && !carries_credential_token(name) { name.as_str() } else { HIDDEN };
            format!("env:{shown}")
        }
        Some(SecretSource::Command(_)) => "command".into(),
        None => "unknown".into(),
    }
}

/// The JSON a key source prints as.
pub fn redacted_secret_value(secret: Option<&SecretSource>) -> serde_json::Value {
    match secret {
        Some(SecretSource::Keychain) => serde_json::json!({ "source": "keychain" }),
        Some(SecretSource::Env(name)) => {
            let shown = if is_posix_env_name(name) && !carries_credential_token(name) { name.as_str() } else { HIDDEN };
            serde_json::json!({ "source": "env", "name": shown })
        }
        Some(SecretSource::Command(_)) => serde_json::json!({ "source": "command", "run": HIDDEN }),
        None => serde_json::json!({ "source": "unknown" }),
    }
}

pub fn key_source_phrase(secret: Option<&SecretSource>) -> String {
    match secret {
        None => "an unknown key source".into(),
        Some(SecretSource::Command(_)) => "a command".into(),
        Some(SecretSource::Keychain) => "the credential store".into(),
        Some(s @ SecretSource::Env(_)) => describe_secret_source(Some(s)),
    }
}

pub fn shares_secret_source(a: Option<&SecretSource>, b: Option<&SecretSource>) -> bool {
    match (a, b) {
        (Some(SecretSource::Env(x)), Some(SecretSource::Env(y))) => x == y,
        (Some(SecretSource::Command(x)), Some(SecretSource::Command(y))) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_shapes() {
        assert!(carries_credential_token("sk-ant-api03-abcdefghijklmnop"));
        assert!(carries_credential_token("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3"));
        assert!(!carries_credential_token("CLAUDE_CODE_MAX_CONTEXT_TOKENS"));
        assert!(!carries_credential_token("z-ai/glm-5.3"));
        assert!(!carries_credential_token("https://openrouter.ai/api"));
    }

    #[test]
    fn base_urls() {
        assert!(check_base_url("https://openrouter.ai/api").is_ok());
        assert_eq!(check_base_url("ftp://x").unwrap_err(), BaseUrlProblem::Scheme(Some("ftp".into())));
        assert_eq!(check_base_url("https://u:p@x.com").unwrap_err(), BaseUrlProblem::Credentials);
        assert_eq!(
            check_base_url("https://x.com/?api_key=1").unwrap_err(),
            BaseUrlProblem::KeyParameter("api_key".into())
        );
        assert_eq!(check_base_url("https://x.com/?page_token=1").unwrap_err(), BaseUrlProblem::KeyParameter("page_token".into()));
        assert!(sends_key_in_clear(&Url::parse("http://gw.example.com").unwrap()));
        assert!(!sends_key_in_clear(&Url::parse("http://127.0.0.1:8000").unwrap()));
    }

    #[test]
    fn redaction() {
        assert_eq!(redact_urls_in("http://user:pass@proxy:8080"), "http://<hidden>@proxy:8080/");
        assert_eq!(redact_base_url("https://x.com/v1?q=1"), "https://x.com/v1?<hidden>");
        assert_eq!(redact_urls_in("user:pass@host"), "<hidden>@host");
    }
}
