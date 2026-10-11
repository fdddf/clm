//! Per-profile cost and token usage, recorded locally from Claude Code's `.claude.json`.

use std::path::{Path, PathBuf};

use chrono::{Datelike, Local, NaiveTime, TimeZone};
use serde_json::{Map, Value, json};

use crate::lock::acquire_file_lock;
use crate::registry::claude_json_path;
use crate::types::{UsagePeriod, UsageSummary};
use crate::util::{self, home, locks_dir, read_json, usage_path, write_json};

/// Runs a read-modify-write of usage.json holding the usage lock; skipped when the lock stays
/// taken, since the next run records what this one missed.
fn with_usage_lock(f: impl FnOnce()) {
    if let Ok(Some(lock)) = acquire_file_lock(&locks_dir().join("usage.lock"), 10_000, 5_000) {
        f();
        drop(lock);
    }
}

pub fn load_usage_store() -> Map<String, Value> {
    match read_json(&usage_path()) {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// The first instant of `period`, in local time; None for all of it.
fn cutoff(period: UsagePeriod) -> Option<chrono::DateTime<Local>> {
    let now = Local::now();
    let midnight = |d: chrono::NaiveDate| Local.from_local_datetime(&d.and_time(NaiveTime::MIN)).earliest();
    let today = now.date_naive();
    match period {
        UsagePeriod::All => None,
        UsagePeriod::Today => midnight(today),
        UsagePeriod::Week => {
            let delta = today.weekday().num_days_from_monday() as i64;
            midnight(today - chrono::Duration::days(delta))
        }
        UsagePeriod::Month => midnight(today.with_day(1).unwrap_or(today)),
    }
}

pub fn summarize(records: &[Value], period: UsagePeriod) -> UsageSummary {
    let cut = cutoff(period);
    let mut summary = UsageSummary::default();
    for record in records {
        let ts = record.get("ts").and_then(|t| t.as_str()).and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
        if let (Some(cut), Some(ts)) = (cut, ts)
            && ts < cut {
                continue;
            }
        summary.cost += record.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0);
        summary.input_tokens += record.get("inputTokens").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
        summary.output_tokens += record.get("outputTokens").and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
    }
    summary
}

pub fn records_of(store: &Map<String, Value>, id: &str) -> Vec<Value> {
    store.get(id).and_then(|p| p.get("records")).and_then(|r| r.as_array()).cloned().unwrap_or_default()
}

/// Where Claude Code keeps a config dir's projects: `~/.claude.json` for the default dir.
fn claude_json_for(config_dir: &Path) -> PathBuf {
    let h = home();
    let default = h.join(".claude");
    let default_resolved = util::realpath(&default).unwrap_or(default.clone());
    let resolved = util::realpath(config_dir).unwrap_or_else(|| config_dir.to_path_buf());
    if resolved == default_resolved { claude_json_path(&h, &default) } else { claude_json_path(&h, config_dir) }
}

fn fingerprint(project: &Map<String, Value>) -> Option<String> {
    let sid = project.get("lastSessionId").and_then(|v| v.as_str()).unwrap_or("");
    let cost = project.get("lastCost").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if sid.is_empty() || cost <= 0.0 {
        return None;
    }
    let num = |k: &str| project.get(k).filter(|v| !v.is_null()).map(|v| v.to_string()).unwrap_or_else(|| "0".into());
    Some(format!(
        "{sid}:{}:{}:{}:{}",
        project.get("lastCost").map(|v| v.to_string()).unwrap_or_default(),
        num("lastTotalInputTokens"),
        num("lastTotalOutputTokens"),
        num("lastDuration")
    ))
}

fn projects_of(config_dir: &Path) -> Option<Map<String, Value>> {
    match read_json(&claude_json_for(config_dir))?.get("projects")? {
        Value::Object(m) => Some(m.clone()),
        _ => None,
    }
}

fn profile_entry<'a>(usage: &'a mut Map<String, Value>, id: &str) -> &'a mut Map<String, Value> {
    let entry = usage.entry(id.to_string()).or_insert_with(|| json!({ "records": [], "seenSessions": {} }));
    if !entry.is_object() {
        *entry = json!({ "records": [], "seenSessions": {} });
    }
    let obj = entry.as_object_mut().unwrap();
    if !obj.get("records").is_some_and(|r| r.is_array()) {
        obj.insert("records".into(), json!([]));
    }
    if !obj.get("seenSessions").is_some_and(|s| s.is_object()) {
        obj.insert("seenSessions".into(), json!({}));
    }
    obj
}

/// Records each project whose last session changed since it was last seen, for `profile_id`
/// or the active claude profile.
pub fn track_usage(profile_id: Option<&str>) {
    let Some(Value::Object(registry)) = read_json(&util::registry_path()) else { return };
    let id = match profile_id {
        Some(id) => id.to_string(),
        None => match registry.get("activeProfiles").and_then(|a| a.get("claude")).and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return,
        },
    };
    let Some(config_dir) = registry.get("profiles").and_then(|p| p.get(&id)).and_then(|p| p.get("configDir")).and_then(|v| v.as_str())
    else {
        return;
    };
    let Some(projects) = projects_of(Path::new(config_dir)) else { return };

    with_usage_lock(|| {
        let mut usage = load_usage_store();
        let now = Local::now();
        let ts = now.format("%Y-%m-%dT%H:%M:%S%:z").to_string();
        let tz = now.format("%:z").to_string();
        let entry = profile_entry(&mut usage, &id);
        let mut changed = false;
        for (path, data) in &projects {
            let Some(project) = data.as_object() else { continue };
            let Some(fp) = fingerprint(project) else { continue };
            let seen = entry.get_mut("seenSessions").and_then(|s| s.as_object_mut()).unwrap();
            if seen.get(path).and_then(|v| v.as_str()) == Some(fp.as_str()) {
                continue;
            }
            seen.insert(path.clone(), json!(fp));
            let cost = project.get("lastCost").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let record = json!({
                "ts": ts,
                "tz": tz,
                "cost": (cost * 1e6).round() / 1e6,
                "inputTokens": project.get("lastTotalInputTokens").filter(|v| v.is_number()).cloned().unwrap_or(json!(0)),
                "outputTokens": project.get("lastTotalOutputTokens").filter(|v| v.is_number()).cloned().unwrap_or(json!(0)),
            });
            entry.get_mut("records").and_then(|r| r.as_array_mut()).unwrap().push(record);
            changed = true;
        }
        if changed {
            let _ = write_json(&usage_path(), &Value::Object(usage), None);
        }
    });
}

/// Marks what a config dir already holds as seen, so usage from before tracking began is not
/// recorded.
pub fn seed_seen_sessions(profile_id: &str, config_dir: &Path) {
    let Some(projects) = projects_of(config_dir) else { return };
    with_usage_lock(|| {
        let mut usage = load_usage_store();
        let entry = profile_entry(&mut usage, profile_id);
        let seen = entry.get_mut("seenSessions").and_then(|s| s.as_object_mut()).unwrap();
        let mut changed = false;
        for (path, data) in &projects {
            let Some(fp) = data.as_object().and_then(fingerprint) else { continue };
            if seen.get(path).is_some_and(|v| !v.is_null() && v != "") {
                continue;
            }
            seen.insert(path.clone(), json!(fp));
            changed = true;
        }
        if changed {
            let _ = write_json(&usage_path(), &Value::Object(usage), None);
        }
    });
}
