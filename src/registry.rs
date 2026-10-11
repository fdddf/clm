//! Reading, migrating and writing `~/.clm/profiles.json`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::checks::{CREDENTIAL_AS_NAME_ERROR, looks_like_credential};
use crate::lock::with_registry_lock;
use crate::types::{ALL_TOOLS, Registry, Tool};
use crate::util::{self, data_dir, exists, read_json, registry_path, shown, usage_path, warn, write_json};

// ─── Paths derived from a config dir ────────────────────────────────

/// Claude Code picks its account file and Keychain item by whether CLAUDE_CONFIG_DIR is set:
/// only the unset variable means `~/.claude.json` and the unhashed Keychain item.
pub fn is_default_claude_dir(home: &Path, config_dir: &Path) -> bool {
    config_dir == home.join(".claude")
}

pub fn claude_json_path(home: &Path, config_dir: &Path) -> PathBuf {
    if is_default_claude_dir(home, config_dir) { home.join(".claude.json") } else { config_dir.join(".claude.json") }
}

pub fn keychain_service(home: &Path, config_dir: &Path) -> String {
    if is_default_claude_dir(home, config_dir) {
        return "Claude Code-credentials".into();
    }
    let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
    let hash = hex::encode(digest);
    format!("Claude Code-credentials-{}", &hash[..8])
}

/// A profile's backup directory: one path segment directly under the tool's backups, since
/// every caller clears it with a recursive remove at some point.
pub fn backup_dir_for(tool: Tool, name: &str) -> Result<PathBuf> {
    let base = data_dir().join("backups").join(tool.name());
    let dir = base.join(name);
    let one_segment = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && dir.parent() == Some(base.as_path())
        && dir.file_name().map(|n| n.to_string_lossy() == name).unwrap_or(false);
    if !one_segment {
        bail!(
            "Profile name '{name}' does not map to a directory of its own inside {} (it resolves to {}); refusing to use it as a backup directory. To recover, remove the '{tool}:{name}' entry from {} by hand.",
            base.display(),
            util::resolve(&dir).display(),
            registry_path().display()
        );
    }
    Ok(dir)
}

// ─── Profile ids and names ──────────────────────────────────────────

pub fn profile_id(tool: Tool, name: &str) -> String {
    format!("{tool}:{name}")
}

/// The form in which two names are compared: a case-insensitive filesystem treats `Work` and
/// `work` as one directory.
pub fn fold_profile_name(name: &str) -> String {
    name.nfkc().collect::<String>().to_lowercase()
}

pub fn validate_profile_name(name: &str) -> Result<()> {
    if looks_like_credential(name) {
        bail!(CREDENTIAL_AS_NAME_ERROR);
    }
    let mut chars = name.chars();
    let valid = matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
    if !valid {
        bail!(
            "Invalid profile name '{name}': must be non-empty, start with a letter or digit, and use only letters, digits, '.', '_' and '-'."
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ProfileRef {
    pub tool: Tool,
    #[allow(dead_code)]
    pub name: String,
    pub id: String,
}

/// `work` when it is unique across tools, or `claude:work`.
pub fn parse_profile_ref(input: &str, registry: &Registry) -> Result<ProfileRef> {
    let refuse_if_key_shaped = |candidates: &[&str]| -> Result<()> {
        if candidates.iter().any(|c| looks_like_credential(c)) {
            bail!(CREDENTIAL_AS_NAME_ERROR);
        }
        Ok(())
    };
    if let Some((maybe_tool, name)) = input.split_once(':') {
        let Some(tool) = Tool::parse(maybe_tool) else {
            refuse_if_key_shaped(&[input, name])?;
            bail!("Unknown tool '{maybe_tool}'. Use one of: claude, codex.");
        };
        let id = profile_id(tool, name);
        if !registry.profiles.contains_key(&id) {
            refuse_if_key_shaped(&[input, name])?;
            bail!("Profile '{id}' not found.");
        }
        return Ok(ProfileRef { tool, name: name.to_string(), id });
    }
    let candidates: Vec<ProfileRef> = ALL_TOOLS
        .iter()
        .filter(|t| registry.profiles.contains_key(&profile_id(**t, input)))
        .map(|t| ProfileRef { tool: *t, name: input.to_string(), id: profile_id(*t, input) })
        .collect();
    match candidates.len() {
        0 => {
            refuse_if_key_shaped(&[input])?;
            bail!("Profile '{input}' not found.")
        }
        1 => Ok(candidates.into_iter().next().unwrap()),
        _ => {
            let list = candidates.iter().map(|c| format!("'{}'", c.id)).collect::<Vec<_>>().join(" or ");
            bail!("'{input}' exists in both claude and codex. Use {list}.")
        }
    }
}

/// The name part of a profile id.
pub fn name_of(id: &str) -> &str {
    id.split_once(':').map(|(_, n)| n).unwrap_or(id)
}

// ─── Loading and saving ─────────────────────────────────────────────

/// Why profiles.json cannot be used, as one line with its remedy; None when it can, or is not
/// there at all. The file is never quoted: it can hold a key command's command line.
pub fn registry_problem() -> Option<String> {
    let path = registry_path();
    let reason = match fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => format!("it could not be opened ({})", e.kind()),
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Err(_) => "it is not valid JSON".into(),
            Ok(Value::Object(obj)) => {
                if is_v1(&obj) || serde_json::from_value::<Registry>(Value::Object(obj)).is_ok() {
                    return None;
                }
                "its contents are not a clm registry".into()
            }
            Ok(_) => "it is not a JSON object".into(),
        },
    };
    Some(format!(
        "{} could not be read: {reason}. Fix it by hand, or move it aside and run 'clm init' to set clm up again.",
        shown(&path)
    ))
}

pub fn no_registry_error() -> anyhow::Error {
    let hint = if util::legacy_dir().join("profiles.json").exists() {
        " It imports your clausona setup from ~/.clausona, which stays as it is."
    } else {
        ""
    };
    anyhow!(registry_problem().unwrap_or_else(|| format!("clm is not initialized. Run `clm init` first.{hint}")))
}

/// Copies the original clausona's data into `~/.clm` when clm has none of its own yet:
/// the registry, usage history, quota cache, file-stored keys and backups. `~/.clausona` is
/// only read, so clausona goes on working beside clm. Returns what was copied.
pub fn import_legacy() -> Result<Vec<String>> {
    let legacy = util::legacy_dir();
    let own = data_dir();
    if own.join("profiles.json").exists() || !legacy.join("profiles.json").is_file() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&own)?;
    let mut copied = Vec::new();
    for (name, mode) in [("profiles.json", Some(0o600)), ("usage.json", None), ("quota.json", None), ("secrets.json", Some(0o600))] {
        let from = legacy.join(name);
        if !from.is_file() {
            continue;
        }
        util::write_atomic(&own.join(name), &fs::read(&from)?, mode)?;
        copied.push(name.to_string());
    }
    let backups = legacy.join("backups");
    if backups.is_dir() && !exists(&own.join("backups")) {
        util::copy_recursive(&backups, &own.join("backups"))?;
        copied.push("backups/".into());
    }
    Ok(copied)
}

fn is_v1(obj: &Map<String, Value>) -> bool {
    obj.contains_key("primarySource") && !obj.contains_key("version")
}

fn migrate_v1(v1: &Map<String, Value>) -> Value {
    let mut profiles = Map::new();
    let active_old = v1.get("activeProfile").and_then(|v| v.as_str()).unwrap_or("");
    let mut active_key = String::new();
    if let Some(Value::Object(old)) = v1.get("profiles") {
        for (name, profile) in old {
            let key = format!("claude:{name}");
            let mut entry = Map::new();
            entry.insert("tool".into(), Value::String("claude".into()));
            if let Value::Object(fields) = profile {
                for (k, v) in fields {
                    entry.insert(k.clone(), v.clone());
                }
            }
            profiles.insert(key.clone(), Value::Object(entry));
            if name == active_old {
                active_key = key;
            }
        }
    }
    if active_key.is_empty() {
        active_key = profiles.keys().next().cloned().unwrap_or_default();
    }
    let mut primary = Map::new();
    if let Some(src) = v1.get("primarySource") {
        primary.insert("claude".into(), src.clone());
    }
    let mut active = Map::new();
    if !active_key.is_empty() {
        active.insert("claude".into(), Value::String(active_key));
    }
    serde_json::json!({ "version": 2, "primarySources": primary, "activeProfiles": active, "profiles": profiles })
}

/// Reads the registry, migrating a v1 file in place. Only call it holding the registry lock.
fn read_registry_locked() -> Result<Option<Registry>> {
    let path = registry_path();
    let Some(Value::Object(raw)) = read_json(&path) else {
        return Ok(None);
    };
    if !is_v1(&raw) {
        return Ok(serde_json::from_value(Value::Object(raw)).ok());
    }
    let bak = PathBuf::from(format!("{}.v1.bak", path.display()));
    if !exists(&bak)
        && let Err(e) = fs::copy(&path, &bak) {
            warn(&format!("migration: could not backup profiles.json: {e}"));
        }
    let migrated = migrate_v1(&raw);
    write_json(&path, &migrated, Some(0o600))?;

    let backups = data_dir().join("backups");
    for (name, ft) in util::read_dir_entries(&backups) {
        if !ft.is_dir() || name == "claude" || name == "codex" {
            continue;
        }
        let dst = backups.join("claude").join(&name);
        let _ = fs::create_dir_all(backups.join("claude"));
        if let Err(e) = fs::rename(backups.join(&name), &dst) {
            warn(&format!("migration: could not move backup {name}: {e}"));
        }
    }

    if let Some(Value::Object(usage)) = read_json(&usage_path())
        && usage.keys().any(|k| !k.contains(':')) {
            let ubak = PathBuf::from(format!("{}.v1.bak", usage_path().display()));
            if !exists(&ubak) {
                let _ = fs::copy(usage_path(), &ubak);
            }
            let renamed: Map<String, Value> = usage
                .into_iter()
                .map(|(k, v)| (if k.contains(':') { k } else { format!("claude:{k}") }, v))
                .collect();
            write_json(&usage_path(), &Value::Object(renamed), None)?;
        }
    eprintln!("  clm migrated registry to v2 (codex support enabled). Open a new terminal to activate the codex() wrapper.");
    Ok(serde_json::from_value(migrated).ok())
}

pub fn load_registry() -> Result<Option<Registry>> {
    let path = registry_path();
    match read_json(&path) {
        Some(Value::Object(raw)) if is_v1(&raw) => with_registry_lock(read_registry_locked),
        Some(Value::Object(raw)) => Ok(serde_json::from_value(Value::Object(raw)).ok()),
        _ => Ok(None),
    }
}

/// The registry, or the error a command that needs one gives.
pub fn require_registry() -> Result<Registry> {
    load_registry()?.ok_or_else(no_registry_error)
}

fn save_registry(registry: &Registry) -> Result<()> {
    let value = serde_json::to_value(registry)?;
    // Owner-only: it holds each API profile's key source and every env map in plain text.
    write_json(&registry_path(), &value, Some(0o600))?;
    Ok(())
}

/// Changes the registry as it stands when the change is written, not as it stood when the
/// caller started: `update` gets a copy read under the lock and returns the registry to save,
/// or None to leave the file untouched. Keep slow work out of it - every writer waits for it.
pub fn update_registry(update: impl FnOnce(Option<Registry>) -> Result<Option<Registry>>) -> Result<Option<Registry>> {
    with_registry_lock(|| {
        let next = update(read_registry_locked()?)?;
        if let Some(r) = &next {
            fs::create_dir_all(data_dir())?;
            save_registry(r)?;
        }
        Ok(next)
    })
}

pub fn set_active_profile(id: &str) -> Result<crate::types::Profile> {
    let saved = update_registry(|current| {
        let mut current = current.ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let tool = current.profiles.get(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?.tool.clone();
        current.active_profiles.insert(tool, id.to_string());
        Ok(Some(current))
    })?;
    Ok(saved.and_then(|r| r.profiles.get(id).cloned()).expect("saved registry holds the profile"))
}
