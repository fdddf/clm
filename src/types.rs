//! The registry as `~/.clm/profiles.json` stores it, compatible with the original clausona's.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tool {
    Claude,
    Codex,
}

pub const ALL_TOOLS: [Tool; 2] = [Tool::Claude, Tool::Codex];

impl Tool {
    pub fn name(self) -> &'static str {
        match self {
            Tool::Claude => "claude",
            Tool::Codex => "codex",
        }
    }

    pub fn parse(s: &str) -> Option<Tool> {
        match s {
            "claude" => Some(Tool::Claude),
            "codex" => Some(Tool::Codex),
            _ => None,
        }
    }

    pub fn product(self) -> &'static str {
        match self {
            Tool::Claude => "Claude Code",
            Tool::Codex => "Codex",
        }
    }
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where an API profile's key is read from. Stored as `{ "source": "keychain" }`,
/// `{ "source": "env", "name": … }` or `{ "source": "command", "run": … }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretSource {
    Keychain,
    Env(String),
    Command(String),
}

impl SecretSource {
    /// The source a stored value names, or None for one clm does not know - a hand edit.
    pub fn from_value(v: &Value) -> Option<SecretSource> {
        let obj = v.as_object()?;
        match obj.get("source")?.as_str()? {
            "keychain" => Some(SecretSource::Keychain),
            "env" => Some(SecretSource::Env(obj.get("name")?.as_str()?.to_string())),
            "command" => Some(SecretSource::Command(obj.get("run")?.as_str()?.to_string())),
            _ => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            SecretSource::Keychain => serde_json::json!({ "source": "keychain" }),
            SecretSource::Env(name) => serde_json::json!({ "source": "env", "name": name }),
            SecretSource::Command(run) => serde_json::json!({ "source": "command", "run": run }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiEndpoint {
    #[serde(default)]
    pub base_url: String,
    /// bearer -> ANTHROPIC_AUTH_TOKEN, api-key -> ANTHROPIC_API_KEY
    #[serde(default)]
    pub auth_scheme: String,
    #[serde(default)]
    pub secret: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ApiEndpoint {
    pub fn secret(&self) -> Option<SecretSource> {
        SecretSource::from_value(&self.secret)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub tool: String,
    /// Absent means "subscription". Anything other than the two kinds is a hand edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<Value>,
    pub config_dir: String,
    #[serde(default)]
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_sessions: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiEndpoint>,
    /// Free-form environment overrides. A hand edit can leave anything here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Profile {
    pub fn new(tool: Tool, config_dir: &str, email: &str) -> Profile {
        Profile {
            tool: tool.name().to_string(),
            kind: None,
            config_dir: config_dir.to_string(),
            email: email.to_string(),
            label: None,
            org_name: None,
            is_primary: None,
            merge_sessions: None,
            api: None,
            env: None,
            extra: Map::new(),
        }
    }

    pub fn tool(&self) -> Tool {
        Tool::parse(&self.tool).unwrap_or(Tool::Claude)
    }

    pub fn is_api(&self) -> bool {
        matches!(&self.kind, Some(Value::String(k)) if k == "api")
    }

    pub fn primary(&self) -> bool {
        self.is_primary.unwrap_or(false)
    }

    pub fn merges(&self) -> bool {
        self.merge_sessions.unwrap_or(false)
    }

    pub fn dir(&self) -> PathBuf {
        PathBuf::from(&self.config_dir)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub version: u32,
    #[serde(default)]
    pub primary_sources: BTreeMap<String, String>,
    #[serde(default)]
    pub active_profiles: BTreeMap<String, String>,
    #[serde(default)]
    pub profiles: IndexMap<String, Profile>,
}

impl Registry {
    pub fn empty() -> Registry {
        Registry { version: 2, primary_sources: BTreeMap::new(), active_profiles: BTreeMap::new(), profiles: IndexMap::new() }
    }

    pub fn primary_source(&self, tool: Tool) -> Option<PathBuf> {
        self.primary_sources.get(tool.name()).map(PathBuf::from)
    }

    pub fn active(&self, tool: Tool) -> Option<&String> {
        self.active_profiles.get(tool.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsagePeriod {
    Today,
    Week,
    Month,
    All,
}

impl UsagePeriod {
    pub fn parse(s: &str) -> Option<UsagePeriod> {
        match s {
            "today" => Some(UsagePeriod::Today),
            "week" => Some(UsagePeriod::Week),
            "month" => Some(UsagePeriod::Month),
            "all" => Some(UsagePeriod::All),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageSummary {
    pub cost: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuotaWindow {
    /// Consumed share of the window, 0-100.
    pub used_percent: f64,
    /// ISO 8601 instant the window rolls over.
    pub resets_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct QuotaWindows {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<QuotaWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly: Option<QuotaWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<QuotaWindow>,
}

impl QuotaWindows {
    pub fn any(&self) -> bool {
        self.session.is_some() || self.weekly.is_some() || self.scoped.is_some()
    }
}

/// `ok` fetched now or still fresh; `expired` rejected; `missing` no credential; `cooldown`
/// rate limited; `error` network or parse failure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QuotaSnapshot {
    #[serde(flatten)]
    pub windows: QuotaWindows,
    pub state: String,
    #[serde(rename = "fetchedAt")]
    pub fetched_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorIssue {
    pub kind: &'static str,
    pub message: String,
    /// Absent means an error; "warning" means the profile works and this is advice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<&'static str>,
}

impl DoctorIssue {
    pub fn error(kind: &'static str, message: String) -> DoctorIssue {
        DoctorIssue { kind, message, severity: None }
    }
    pub fn warning(kind: &'static str, message: String) -> DoctorIssue {
        DoctorIssue { kind, message, severity: Some("warning") }
    }
    pub fn is_warning(&self) -> bool {
        self.severity.is_some()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorResult {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub config_dir: String,
    pub is_primary: bool,
    pub healthy: bool,
    pub issues: Vec<DoctorIssue>,
}

/// An account found signed in on this machine.
#[derive(Clone, Debug)]
pub struct DiscoveredAccount {
    pub tool: Tool,
    pub config_dir: PathBuf,
    pub email: String,
    pub org_name: Option<String>,
    pub is_primary: bool,
}
