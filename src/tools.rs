//! What clm knows about each tool: where it keeps its account and credential, what a
//! profile shares with the primary, its quota endpoint and how its sign-in is renewed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::lock::{DirLockOptions, acquire_dir_lock};
use crate::registry::{claude_json_path, is_default_claude_dir, keychain_service};
use crate::secrets::{run_capture, write_keychain_item};
use crate::types::{QuotaWindows, Tool};
use crate::util::{self, home, now_ms, read_json, write_atomic};

pub fn default_config_dir(tool: Tool) -> PathBuf {
    match tool {
        Tool::Claude => home().join(".claude"),
        Tool::Codex => home().join(".codex"),
    }
}

pub fn config_env_var(tool: Tool) -> &'static str {
    match tool {
        Tool::Claude => "CLAUDE_CONFIG_DIR",
        Tool::Codex => "CODEX_HOME",
    }
}

pub fn binary(tool: Tool) -> &'static str {
    tool.name()
}

/// `.claude`, `.claude-<x>`; `.codex`, `.codex-<x>`.
pub fn matches_config_dir_name(tool: Tool, name: &str) -> bool {
    let prefix = match tool {
        Tool::Claude => ".claude",
        Tool::Codex => ".codex",
    };
    name == prefix || name.strip_prefix(prefix).and_then(|r| r.strip_prefix('-')).is_some_and(|r| !r.is_empty())
}

#[derive(Clone, Debug)]
pub struct AccountInfo {
    pub email: String,
    pub org_name: Option<String>,
}

pub fn read_account_info(tool: Tool, config_dir: &Path) -> Option<AccountInfo> {
    match tool {
        Tool::Claude => {
            let parsed = read_json(&claude_json_path(&home(), config_dir))?;
            let account = parsed.get("oauthAccount")?;
            let email = account.get("emailAddress")?.as_str()?.to_string();
            if email.is_empty() {
                return None;
            }
            let org_name = account.get("organizationName").and_then(|v| v.as_str()).map(String::from);
            Some(AccountInfo { email, org_name })
        }
        Tool::Codex => {
            let parsed = read_json(&config_dir.join("auth.json"))?;
            let tokens = parsed.get("tokens");
            if let Some(id_token) = tokens.and_then(|t| t.get("id_token")).and_then(|v| v.as_str())
                && let Some(payload) = decode_jwt_payload(id_token)
                    && let Some(email) = payload.get("email").and_then(|v| v.as_str()) {
                        let org_name = payload
                            .get("https://api.openai.com/auth")
                            .and_then(|a| a.get("organizations"))
                            .and_then(|o| o.get(0))
                            .and_then(|o| o.get("title"))
                            .and_then(|t| t.as_str())
                            .map(String::from);
                        return Some(AccountInfo { email: email.to_string(), org_name });
                    }
            let account_id = tokens.and_then(|t| t.get("account_id")).and_then(|v| v.as_str())?;
            Some(AccountInfo { email: account_id.to_string(), org_name: None })
        }
    }
}

pub fn decode_jwt_payload(token: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let body = parts[1].trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

// ─── What a profile shares ──────────────────────────────────────────

/// Written into a directory `add` creates until the profile is registered.
pub const ADD_PENDING_MARKER: &str = ".clausona-pending";

const CLAUDE_SKIP: &[&str] = &[
    ".claude.json",
    ".credentials.json",
    "image-cache",
    "statsig",
    "plugins",
    ".last-update-result.json",
    "gh-pr-status-cache.json",
    ".session-stats.json",
];
/// Session-keyed state, which follows the session-separation choice.
const CLAUDE_SESSION_SCOPED: &[&str] = &["projects", "jobs", "teams"];

const CODEX_SHARED: &[&str] = &[
    "config.toml",
    "hooks.json",
    "rules",
    ".sandbox_migration",
    "skills",
    "plugins",
    "agents",
    "prompts",
    "vendor_imports",
    "pets",
    ".personality_migration",
];
const CODEX_SESSION_SET: &[&str] = &[
    "sessions",
    "archived_sessions",
    "session_index.jsonl",
    "history.jsonl",
    "attachments",
    "visualizations",
    "thread-writer-locks",
    "rollout-migrations",
];
/// The thread store, shared with merged sessions as one unit (macOS and Linux).
const CODEX_SESSION_DATABASES: &[&str] = &["state_5.sqlite", "goals_1.sqlite", "thread_history_1.sqlite"];

pub fn is_sqlite_file(name: &str) -> bool {
    ["", "-wal", "-shm", "-journal"].iter().any(|s| name.ends_with(&format!(".sqlite{s}")))
}

pub fn is_sqlite_companion(name: &str) -> bool {
    ["-wal", "-shm", "-journal"].iter().any(|s| name.ends_with(&format!(".sqlite{s}")))
}

fn codex_shared_allow(name: &str, merge: bool) -> bool {
    if is_sqlite_file(name) {
        return merge && CODEX_SESSION_DATABASES.contains(&name);
    }
    if CODEX_SHARED.contains(&name)
        || name.ends_with(".config.toml")
        || (name.starts_with("AGENTS") && name.ends_with(".md"))
    {
        return true;
    }
    merge && CODEX_SESSION_SET.contains(&name)
}

/// Whether a tool names only the entries it shares (Codex), rather than those it does not.
pub fn names_shared_entries(tool: Tool) -> bool {
    tool == Tool::Codex
}

/// The skip set of a tool that names what it does not share (Claude).
pub fn shared_skip_set(tool: Tool, merge: bool) -> Vec<&'static str> {
    match tool {
        Tool::Claude => {
            let mut v = CLAUDE_SKIP.to_vec();
            if !merge {
                v.extend_from_slice(CLAUDE_SESSION_SCOPED);
            }
            v
        }
        Tool::Codex => Vec::new(),
    }
}

/// Whether the primary's entry `name` stays out of a profile.
pub fn should_skip_share(tool: Tool, name: &str, merge: bool) -> bool {
    if name == ADD_PENDING_MARKER {
        return true;
    }
    match tool {
        Tool::Codex => !codex_shared_allow(name, merge),
        Tool::Claude => shared_skip_set(tool, merge).contains(&name),
    }
}

/// Shared files the tool saves whole, by renaming a new file over the old one.
pub fn rewrites_whole(tool: Tool, name: &str) -> bool {
    match tool {
        Tool::Claude => matches!(name, "settings.json" | "CLAUDE.md" | "keybindings.json"),
        Tool::Codex => name == "config.toml" || name.ends_with(".config.toml") || name == "hooks.json",
    }
}

/// Entries a profile that linked the primary's keeps as a copy, in place of the link.
pub fn copied_when_unlinked(tool: Tool) -> &'static [&'static str] {
    match tool {
        Tool::Codex => &[".env"],
        Tool::Claude => &[],
    }
}

/// Unix sockets the tool binds inside its config dir, and what each is for.
pub fn unix_sockets(tool: Tool) -> &'static [(&'static str, &'static str)] {
    match tool {
        Tool::Codex => &[("app-server-daemon/daemon-updater.sock", "the app-server daemon's auto-update")],
        Tool::Claude => &[],
    }
}

/// What a Codex profile's link to one of the primary's own entries does: (wrong_account, why).
pub fn unshared_risk(name: &str) -> (bool, &'static str) {
    if matches!(name, "auth.json" | ".credentials.json" | "secrets") {
        return (true, "so Codex in this profile uses the primary's credentials");
    }
    if name == ".env" {
        return (true, "so Codex in this profile loads the primary's .env, and any API keys in it, at start");
    }
    if name == "app-server-control" {
        return (
            true,
            "so Codex in this profile talks to the primary's app-server daemon and runs on the primary's account and quota",
        );
    }
    if name == "app-server-daemon" {
        return (
            true,
            "so this profile and the primary share one app-server daemon's pid files and lock, and stopping or starting the daemon in one does it to the other's",
        );
    }
    if name.starts_with("memories") {
        return (
            false,
            "so the conversation summaries Codex adds to future prompts are shared: one account's conversations reach the other account's prompts",
        );
    }
    if CODEX_SESSION_SET.contains(&name) || CODEX_SESSION_DATABASES.contains(&name) {
        return (false, "but this profile keeps its sessions separate from the primary's");
    }
    if is_sqlite_file(name) {
        return (
            false,
            "so this profile reads and writes the primary's Codex database (threads, goals, queues) instead of its own",
        );
    }
    (false, "but Codex keeps it for each CODEX_HOME, so this profile shares it with the primary's account")
}

// ─── Credentials ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Credential {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// ms epoch.
    pub expires_at: Option<i64>,
    pub headers: Vec<(String, String)>,
}

/// The account Claude Code files its Keychain item under: USER, or "claude-code-user".
pub fn claude_keychain_account() -> String {
    let name = std::env::var("USER").unwrap_or_default();
    static RE: OnceLock<Regex> = OnceLock::new();
    let ok = RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap()).is_match(&name);
    if ok { name } else { "claude-code-user".into() }
}

pub fn has_keychain_credential(service: &str) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", &claude_keychain_account()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn parse_stored(raw: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str(raw).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn to_claude_credential(blob: &Map<String, Value>) -> Option<Credential> {
    let oauth = blob.get("claudeAiOauth")?;
    let access = oauth.get("accessToken")?.as_str()?;
    if access.is_empty() {
        return None;
    }
    Some(Credential {
        access_token: access.to_string(),
        refresh_token: oauth.get("refreshToken").and_then(|v| v.as_str()).map(String::from),
        expires_at: oauth.get("expiresAt").and_then(|v| v.as_f64()).map(|f| f as i64),
        headers: Vec::new(),
    })
}

fn credentials_file(config_dir: &Path) -> PathBuf {
    config_dir.join(".credentials.json")
}

fn read_file_blob(config_dir: &Path) -> Option<Map<String, Value>> {
    parse_stored(&std::fs::read_to_string(credentials_file(config_dir)).ok()?)
}

pub fn has_fallback_credential(config_dir: &Path) -> bool {
    read_file_blob(config_dir).and_then(|b| to_claude_credential(&b)).is_some()
}

#[derive(Clone, Copy, PartialEq)]
enum Store {
    Keychain,
    File,
}

enum Lookup {
    Found(Map<String, Value>, Store),
    Absent,
    Unreadable,
}

/// `security -w` prints the data as hex once any byte is outside printable ASCII.
fn decode_keychain_output(stdout: &str) -> String {
    let t = stdout.trim();
    let is_hex = t.len() >= 2 && t.len().is_multiple_of(2) && t[..2].eq_ignore_ascii_case("7b") && t.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex
        && let Ok(bytes) = hex::decode(t) {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    stdout.to_string()
}

/// Reads in Claude Code's order: on macOS the Keychain, then `.credentials.json`; elsewhere
/// only the file.
fn lookup_stored_blob(config_dir: &Path) -> Lookup {
    if cfg!(target_os = "macos") {
        let service = keychain_service(&home(), config_dir);
        let account = claude_keychain_account();
        let output = Command::new("security")
            .args(["find-generic-password", "-s", &service, "-a", &account, "-w"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        match output {
            Ok(out) if out.status.success() => {
                if let Some(blob) = parse_stored(&decode_keychain_output(&String::from_utf8_lossy(&out.stdout))) {
                    return Lookup::Found(blob, Store::Keychain);
                }
            }
            Ok(out) => {
                let code = out.status.code().unwrap_or(1);
                // errSecItemNotFound and errSecInteractionNotAllowed read as an empty Keychain.
                if code != 44 && code != 36 {
                    return Lookup::Unreadable;
                }
            }
            Err(_) => {}
        }
    }
    match read_file_blob(config_dir) {
        Some(blob) => Lookup::Found(blob, Store::File),
        None => Lookup::Absent,
    }
}

pub fn read_credential(tool: Tool, config_dir: &Path) -> Option<Credential> {
    match tool {
        Tool::Claude => match lookup_stored_blob(config_dir) {
            Lookup::Found(blob, _) => to_claude_credential(&blob),
            _ => None,
        },
        Tool::Codex => to_codex_credential(&read_codex_auth(config_dir)?),
    }
}

fn write_stored_blob(config_dir: &Path, blob: &Map<String, Value>, store: Store) -> Result<()> {
    let serialized = serde_json::to_string(blob)?;
    if store == Store::Keychain {
        let service = keychain_service(&home(), config_dir);
        return write_keychain_item(&service, &claude_keychain_account(), &serialized);
    }
    let target = credentials_file(config_dir);
    write_atomic(&target, serialized.as_bytes(), Some(0o600))?;
    let back = read_file_blob(config_dir);
    let wanted = blob.get("claudeAiOauth").and_then(|o| o.get("accessToken"));
    if back.as_ref().and_then(|b| b.get("claudeAiOauth")).and_then(|o| o.get("accessToken")) != wanted {
        bail!("{} did not take the renewed credential", target.display());
    }
    Ok(())
}

fn read_codex_auth(config_dir: &Path) -> Option<Map<String, Value>> {
    match read_json(&config_dir.join("auth.json"))? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn to_codex_credential(auth: &Map<String, Value>) -> Option<Credential> {
    let tokens = auth.get("tokens")?;
    let access = tokens.get("access_token")?.as_str()?;
    if access.is_empty() {
        return None;
    }
    let exp = decode_jwt_payload(access).and_then(|p| p.get("exp").and_then(|v| v.as_f64()));
    let mut headers = Vec::new();
    if let Some(id) = tokens.get("account_id").and_then(|v| v.as_str()) {
        headers.push(("chatgpt-account-id".to_string(), id.to_string()));
    }
    Some(Credential {
        access_token: access.to_string(),
        refresh_token: tokens.get("refresh_token").and_then(|v| v.as_str()).map(String::from),
        expires_at: exp.map(|s| (s * 1000.0) as i64),
        headers,
    })
}

// ─── HTTP ───────────────────────────────────────────────────────────

/// A non-2xx answer from a quota or token endpoint.
#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub retry_after: Option<String>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "endpoint returned {}", self.status)
    }
}

impl std::error::Error for HttpError {}

pub const QUOTA_TIMEOUT: Duration = Duration::from_millis(5000);

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(QUOTA_TIMEOUT).build()
}

fn http_json(request: ureq::Request, body: Option<Value>) -> Result<Value> {
    let response = match body {
        Some(b) => request.send_json(b),
        None => request.call(),
    };
    match response {
        Ok(resp) => Ok(resp.into_json::<Value>()?),
        Err(ureq::Error::Status(status, resp)) => {
            Err(HttpError { status, retry_after: resp.header("retry-after").map(String::from) }.into())
        }
        Err(e) => Err(anyhow!("{e}")),
    }
}

const CLAUDE_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
const CLAUDE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CODEX_USAGE_URL: &str = "https://chatgpt.com/backend-api/codex/usage";
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

pub fn fetch_quota(tool: Tool, credential: &Credential) -> Result<Option<QuotaWindows>> {
    match tool {
        Tool::Claude => {
            let req = agent()
                .get(CLAUDE_USAGE_URL)
                .set("Authorization", &format!("Bearer {}", credential.access_token))
                .set("Content-Type", "application/json");
            Ok(crate::quota::parse_claude_quota(&http_json(req, None)?))
        }
        Tool::Codex => {
            let user_agent = format!("codex_cli_rs/clm ({}; {})", std::env::consts::OS, std::env::consts::ARCH);
            let mut req = agent()
                .get(CODEX_USAGE_URL)
                .set("Authorization", &format!("Bearer {}", credential.access_token))
                .set("User-Agent", &user_agent)
                .set("originator", "codex_cli_rs");
            for (k, v) in &credential.headers {
                req = req.set(k, v);
            }
            Ok(crate::quota::parse_codex_quota(&http_json(req, None)?))
        }
    }
}

/// Renews via the OAuth refresh grant and persists the result before returning: the provider
/// rotates the refresh token, and the old one is dead the moment it answers. None when it
/// changed nothing because the tool itself was renewing the same credential at the time.
pub fn renew_credential(tool: Tool, config_dir: &Path, credential: &Credential) -> Result<Option<Credential>> {
    match tool {
        Tool::Claude => renew_claude(config_dir, credential),
        Tool::Codex => renew_codex(config_dir, credential).map(Some),
    }
}

const REFRESH_LOCK: DirLockOptions = DirLockOptions { stale_ms: 60_000, update_ms: 5_000, wait_ms: 0, retry_ms: 100 };
const STORAGE_WRITE_LOCK: DirLockOptions = DirLockOptions { stale_ms: 15_000, update_ms: 7_500, wait_ms: 25_000, retry_ms: 100 };

fn renew_claude(config_dir: &Path, credential: &Credential) -> Result<Option<Credential>> {
    if credential.refresh_token.is_none() {
        bail!("no refresh token stored for this profile");
    }
    // Claude Code's own refresh locks, in its order: then a running Claude Code and clm
    // never spend the same refresh token.
    let Some(current_lock) = acquire_dir_lock(&config_dir.join(".oauth_refresh.lock"), &REFRESH_LOCK)? else {
        return Ok(None);
    };
    let legacy = PathBuf::from(format!("{}.lock", util::real_or_resolved(config_dir).display()));
    let legacy_lock = match acquire_dir_lock(&legacy, &REFRESH_LOCK) {
        Ok(Some(l)) => Some(l),
        Ok(None) => return Ok(None),
        Err(_) => None,
    };
    let result = renew_claude_locked(config_dir, credential);
    drop(legacy_lock);
    drop(current_lock);
    result.map(Some)
}

fn renew_claude_locked(config_dir: &Path, credential: &Credential) -> Result<Credential> {
    let (before_blob, before_store) = match lookup_stored_blob(config_dir) {
        Lookup::Unreadable => bail!("the stored credential could not be read to check it before renewal"),
        Lookup::Absent => bail!("no credential is stored for this profile any more"),
        Lookup::Found(b, s) => (b, s),
    };
    let current = to_claude_credential(&before_blob).ok_or_else(|| anyhow!("no credential is stored for this profile any more"))?;
    if current.access_token != credential.access_token {
        return Ok(current);
    }
    let posted = current.refresh_token.clone().ok_or_else(|| anyhow!("no refresh token stored for this profile"))?;

    let data = http_json(
        agent().post(CLAUDE_TOKEN_URL).set("Content-Type", "application/json"),
        Some(json!({ "grant_type": "refresh_token", "refresh_token": posted, "client_id": CLAUDE_CLIENT_ID })),
    )?;
    let access = data
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("refresh response carried no access token"))?
        .to_string();

    let write_lock = acquire_dir_lock(&config_dir.join(".storage-write.lock"), &STORAGE_WRITE_LOCK).ok().flatten();
    let reread = lookup_stored_blob(config_dir);
    if let Lookup::Found(blob, _) = &reread {
        let stored = blob.get("claudeAiOauth").and_then(|o| o.get("refreshToken")).and_then(|v| v.as_str());
        if stored != Some(posted.as_str()) && stored != Some("") {
            return to_claude_credential(blob).ok_or_else(|| anyhow!("the sign-in was removed while it was being renewed"));
        }
    }
    let unreadable = matches!(reread, Lookup::Unreadable);
    let (mut blob, store) = match reread {
        Lookup::Found(b, s) => (b, s),
        _ => (before_blob, before_store),
    };
    let now = now_ms();
    let mut oauth = blob.get("claudeAiOauth").and_then(|o| o.as_object()).cloned().unwrap_or_default();
    oauth.insert("accessToken".into(), json!(access));
    let refresh = data.get("refresh_token").and_then(|v| v.as_str()).map(String::from).unwrap_or(posted);
    oauth.insert("refreshToken".into(), json!(refresh));
    if let Some(e) = data.get("expires_in").and_then(|v| v.as_f64()).filter(|e| *e > 0.0) {
        oauth.insert("expiresAt".into(), json!(now + (e * 1000.0) as i64));
    }
    if let Some(e) = data.get("refresh_token_expires_in").and_then(|v| v.as_f64()).filter(|e| *e > 0.0) {
        oauth.insert("refreshTokenExpiresAt".into(), json!(now + (e * 1000.0) as i64));
    }
    if let Some(scope) = data.get("scope").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        oauth.insert("scopes".into(), json!(scope.split(' ').collect::<Vec<_>>()));
    }
    let expires_at = oauth.get("expiresAt").and_then(|v| v.as_f64()).map(|f| f as i64);
    blob.insert("claudeAiOauth".into(), Value::Object(oauth));
    if unreadable {
        if write_stored_blob(config_dir, &blob, Store::Keychain).is_err() {
            write_stored_blob(config_dir, &blob, Store::File)?;
        }
    } else {
        write_stored_blob(config_dir, &blob, store)?;
    }
    drop(write_lock);
    Ok(Credential { access_token: access, refresh_token: Some(refresh), expires_at, headers: Vec::new() })
}

fn renew_codex(config_dir: &Path, credential: &Credential) -> Result<Credential> {
    let refresh = credential.refresh_token.clone().ok_or_else(|| anyhow!("no refresh token stored for this profile"))?;
    let data = http_json(
        agent().post(CODEX_TOKEN_URL).set("Content-Type", "application/json"),
        Some(json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": CODEX_CLIENT_ID,
            "scope": "openid profile email",
        })),
    )?;
    let access = data
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("refresh response carried no access token"))?
        .to_string();
    let mut auth = read_codex_auth(config_dir).unwrap_or_default();
    let mut tokens = auth.get("tokens").and_then(|t| t.as_object()).cloned().unwrap_or_default();
    tokens.insert("access_token".into(), json!(access));
    tokens.insert(
        "refresh_token".into(),
        json!(data.get("refresh_token").and_then(|v| v.as_str()).unwrap_or(&refresh)),
    );
    if let Some(id) = data.get("id_token").and_then(|v| v.as_str()) {
        tokens.insert("id_token".into(), json!(id));
    }
    auth.insert("tokens".into(), Value::Object(tokens));
    auth.insert("last_refresh".into(), json!(util::iso_now()));
    let target = config_dir.join("auth.json");
    write_atomic(&target, util::to_pretty(&Value::Object(auth.clone())).as_bytes(), Some(0o600))?;
    let back = read_codex_auth(config_dir);
    if back.as_ref().and_then(|a| a.get("tokens")).and_then(|t| t.get("access_token")).and_then(|v| v.as_str())
        != Some(access.as_str())
    {
        bail!("{} did not take the renewed credential", target.display());
    }
    Ok(to_codex_credential(&auth).unwrap_or(Credential { access_token: access, refresh_token: None, expires_at: None, headers: Vec::new() }))
}

// ─── Sign-in ────────────────────────────────────────────────────────

fn login_command(tool: Tool, config_dir: &Path) -> Command {
    let mut cmd = Command::new(binary(tool));
    match tool {
        Tool::Claude => {
            cmd.args(["auth", "login"]);
            cmd.env_remove("CLAUDE_CONFIG_DIR");
            if !is_default_claude_dir(&home(), config_dir) {
                cmd.env("CLAUDE_CONFIG_DIR", config_dir);
            }
        }
        Tool::Codex => {
            cmd.arg("login");
            cmd.env("CODEX_HOME", config_dir);
        }
    }
    cmd
}

/// The tool's own interactive sign-in into `config_dir`.
pub fn run_login(tool: Tool, config_dir: &Path) -> bool {
    login_command(tool, config_dir).status().map(|s| s.success()).unwrap_or(false)
}

pub enum SignInCheck {
    Ok,
    SignedOut(String),
    Unknown(String),
}

/// After a login that reported success: whether Claude Code now holds a stored claude.ai
/// credential for `config_dir`, asked with every variable that could authenticate it otherwise
/// cleared. Codex reads its account from the same auth.json that holds its tokens.
pub fn verify_sign_in(tool: Tool, config_dir: &Path) -> SignInCheck {
    if tool != Tool::Claude {
        return SignInCheck::Ok;
    }
    let mut cmd = Command::new("claude");
    cmd.args(["auth", "status", "--json"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.env_remove("CLAUDE_CONFIG_DIR");
    if !is_default_claude_dir(&home(), config_dir) {
        cmd.env("CLAUDE_CONFIG_DIR", config_dir);
    }
    for key in crate::env::CREDENTIAL_ENV_KEYS.iter().chain(crate::env::ROUTING_ENV_KEYS) {
        cmd.env_remove(key);
    }
    cmd.env_remove("CLAUDE_CODE_SIMPLE");
    let Ok(mut child) = cmd.spawn() else {
        return SignInCheck::Unknown("could not run 'claude auth status'".into());
    };
    let deadline = now_ms() + 30_000;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if now_ms() < deadline => util::sleep_ms(100),
            _ => {
                let _ = child.kill();
                break None;
            }
        }
    };
    let Some(status) = status else {
        return SignInCheck::Unknown("'claude auth status' did not answer within 30s".into());
    };
    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        let _ = out.read_to_string(&mut stdout);
    }
    let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "null".into());
    let parsed = match (stdout.find('{'), stdout.rfind('}')) {
        (Some(a), Some(b)) if a < b => serde_json::from_str::<Value>(&stdout[a..=b]).ok(),
        _ => None,
    };
    let Some(Value::Object(st)) = parsed else {
        return SignInCheck::Unknown(format!("'claude auth status' exited {code} with no JSON answer"));
    };
    match st.get("loggedIn") {
        Some(Value::Bool(false)) => return SignInCheck::SignedOut("'claude auth status' reports it is not logged in".into()),
        Some(Value::Bool(true)) => {}
        _ => return SignInCheck::Unknown("'claude auth status' did not say whether it is logged in".into()),
    }
    let method = st.get("authMethod").cloned().unwrap_or(Value::Null);
    if method != json!("claude.ai") {
        return SignInCheck::Unknown(format!("'claude auth status' reports sign-in method {method}, not claude.ai"));
    }
    if !status.success() {
        return SignInCheck::Unknown(format!("'claude auth status' exited {code}"));
    }
    SignInCheck::Ok
}

/// Whether the tool holds a stored credential for a Claude profile (Keychain or fallback file
/// on macOS; the file elsewhere), or an account for a Codex one.
pub fn already_signed_in(tool: Tool, config_dir: &Path) -> bool {
    match tool {
        Tool::Claude => {
            let resolved = util::realpath(config_dir).unwrap_or_else(|| config_dir.to_path_buf());
            let service = keychain_service(&home(), &resolved);
            let stored = has_keychain_credential(&service)
                || (cfg!(target_os = "macos") && has_fallback_credential(config_dir))
                || (!cfg!(target_os = "macos") && read_credential(tool, config_dir).is_some());
            stored && read_account_info(tool, config_dir).is_some()
        }
        Tool::Codex => read_account_info(tool, config_dir).is_some(),
    }
}

/// `codex` processes running with CODEX_HOME at `config_dir`.
pub fn codex_processes_for(config_dir: &Path) -> Vec<u32> {
    let home = util::real_or_resolved(config_dir);
    let normalize = |v: &str| util::real_or_resolved(&util::expand_tilde(v));
    let mut found = Vec::new();
    if cfg!(target_os = "linux") {
        for name in util::read_dir_names(Path::new("/proc")) {
            let Ok(pid) = name.parse::<u32>() else { continue };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.trim() != "codex" {
                continue;
            }
            let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
            for var in environ.split(|b| *b == 0) {
                let var = String::from_utf8_lossy(var);
                if let Some(v) = var.strip_prefix("CODEX_HOME=")
                    && normalize(v) == home {
                        found.push(pid);
                    }
            }
        }
    } else if cfg!(target_os = "macos") {
        let (_, pids) = run_capture("pgrep", &["-x", "codex"], None);
        for pid in pids.split_whitespace().filter_map(|p| p.parse::<u32>().ok()) {
            let (_, line) = run_capture("ps", &["-wwE", "-o", "command=", "-p", &pid.to_string()], None);
            let text = format!(" {}", line.trim());
            let marker = " CODEX_HOME=";
            let mut at = text.find(marker);
            static VAR: OnceLock<Regex> = OnceLock::new();
            let var = VAR.get_or_init(|| Regex::new(r" [A-Za-z_][A-Za-z0-9_]*=").unwrap());
            while let Some(i) = at {
                let rest = &text[i + marker.len()..];
                let value = var.find(rest).map(|m| &rest[..m.start()]).unwrap_or(rest);
                if normalize(value) == home {
                    found.push(pid);
                }
                at = text[i + 1..].find(marker).map(|j| j + i + 1);
            }
        }
    }
    found
}
