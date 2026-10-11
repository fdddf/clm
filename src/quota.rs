//! Plan quota: each tool's usage endpoint, read with the credential the tool stored, cached
//! for five minutes in `~/.clm/quota.json`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::lock::acquire_file_lock;
use crate::tools::{self, Credential, HttpError};
use crate::types::{QuotaSnapshot, QuotaWindow, QuotaWindows, Tool};
use crate::util::{data_dir, now_ms, read_json, write_json};

const QUOTA_FRESH_MS: i64 = 5 * 60 * 1000;
const QUOTA_DEFAULT_COOLDOWN_MS: i64 = 60 * 60 * 1000;
/// Renew a hair before expiry so a token cannot lapse mid-request.
const RENEW_MARGIN_MS: i64 = 60 * 1000;
const LOCK_STALE_MS: i64 = 60 * 1000;

fn to_percent(v: Option<&Value>) -> Option<f64> {
    let n = v?.as_f64()?;
    n.is_finite().then(|| n.clamp(0.0, 100.0))
}

fn to_iso(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    let parsed = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    Some(parsed.with_timezone(&chrono::Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

fn iso_from_epoch_seconds(v: Option<&Value>) -> Option<String> {
    let n = v?.as_f64()?;
    if !n.is_finite() || n <= 0.0 {
        return None;
    }
    let dt = chrono::DateTime::from_timestamp_millis((n * 1000.0) as i64)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

fn claude_window(v: Option<&Value>) -> Option<QuotaWindow> {
    let obj = v?.as_object()?;
    let used = to_percent(obj.get("utilization"))?;
    Some(QuotaWindow { used_percent: used, resets_at: to_iso(obj.get("resets_at")), label: None })
}

/// Parses `GET https://api.anthropic.com/api/oauth/usage`.
pub fn parse_claude_quota(raw: &Value) -> Option<QuotaWindows> {
    let obj = raw.as_object()?;
    let mut scoped: Option<QuotaWindow> = None;
    if let Some(Value::Array(limits)) = obj.get("limits") {
        for entry in limits {
            let Some(e) = entry.as_object() else { continue };
            if e.get("kind").and_then(|k| k.as_str()) != Some("weekly_scoped") {
                continue;
            }
            let Some(used) = to_percent(e.get("percent")) else { continue };
            let label = e
                .get("scope")
                .and_then(|s| s.get("model"))
                .and_then(|m| m.get("display_name"))
                .and_then(|d| d.as_str())
                .filter(|s| !s.is_empty());
            let Some(label) = label else { continue };
            if scoped.as_ref().is_none_or(|b| used > b.used_percent) {
                scoped = Some(QuotaWindow { used_percent: used, resets_at: to_iso(e.get("resets_at")), label: Some(label.into()) });
            }
        }
    }
    let windows = QuotaWindows { session: claude_window(obj.get("five_hour")), weekly: claude_window(obj.get("seven_day")), scoped };
    windows.any().then_some(windows)
}

fn codex_window(v: Option<&Value>) -> Option<(QuotaWindow, f64)> {
    let obj = v?.as_object()?;
    let used = to_percent(obj.get("used_percent"))?;
    let seconds = obj.get("limit_window_seconds").and_then(|s| s.as_f64()).unwrap_or(0.0);
    Some((QuotaWindow { used_percent: used, resets_at: iso_from_epoch_seconds(obj.get("reset_at")), label: None }, seconds))
}

/// Parses `GET https://chatgpt.com/backend-api/codex/usage`: windows are classified by their
/// declared width, a day or less being the session one.
pub fn parse_codex_quota(raw: &Value) -> Option<QuotaWindows> {
    let obj = raw.as_object()?;
    let rate = obj.get("rate_limit");
    let mut windows = QuotaWindows::default();
    for key in ["primary_window", "secondary_window"] {
        if let Some((w, seconds)) = codex_window(rate.and_then(|r| r.get(key))) {
            if seconds > 0.0 && seconds <= 86_400.0 {
                windows.session = Some(w);
            } else {
                windows.weekly = Some(w);
            }
        }
    }
    if let Some(Value::Array(extra)) = obj.get("additional_rate_limits") {
        for entry in extra {
            let Some(label) = entry.get("limit_name").and_then(|l| l.as_str()).filter(|s| !s.is_empty()) else { continue };
            let Some((mut w, _)) = codex_window(entry.get("rate_limit").and_then(|r| r.get("primary_window"))) else { continue };
            if windows.scoped.as_ref().is_none_or(|s| w.used_percent > s.used_percent) {
                w.label = Some(label.into());
                windows.scoped = Some(w);
            }
        }
    }
    windows.any().then_some(windows)
}

fn cooldown_until(retry_after: Option<&str>, now: i64) -> i64 {
    match retry_after.and_then(|r| r.trim().parse::<f64>().ok()) {
        Some(s) if s.is_finite() && s > 0.0 => now + (s.min(86_400.0) * 1000.0) as i64,
        _ => now + QUOTA_DEFAULT_COOLDOWN_MS,
    }
}

#[derive(Serialize, Deserialize, Default)]
struct QuotaCache {
    version: u32,
    #[serde(default)]
    cooldowns: HashMap<String, i64>,
    #[serde(default)]
    profiles: Map<String, Value>,
}

fn cache_path() -> PathBuf {
    data_dir().join("quota.json")
}

fn read_cache() -> QuotaCache {
    match read_json(&cache_path()).and_then(|v| serde_json::from_value::<QuotaCache>(v).ok()) {
        Some(c) if c.version == 1 => c,
        _ => QuotaCache { version: 1, ..Default::default() },
    }
}

fn cached_snapshot(cache: &QuotaCache, id: &str) -> Option<QuotaSnapshot> {
    serde_json::from_value(cache.profiles.get(id)?.clone()).ok()
}

/// A failure that keeps what was last known, stamped with when it was true.
fn degraded(state: &str, cached: Option<&QuotaSnapshot>, now: i64) -> QuotaSnapshot {
    match cached {
        Some(c) if c.windows.any() => QuotaSnapshot { windows: c.windows.clone(), state: state.into(), fetched_at: c.fetched_at },
        _ => QuotaSnapshot { windows: QuotaWindows::default(), state: state.into(), fetched_at: now },
    }
}

pub struct QuotaTarget {
    pub id: String,
    pub tool: Tool,
    pub config_dir: PathBuf,
}

/// Renews under a per-profile lock; None when renewal is impossible, failed, or another
/// process holds the lock.
fn renew(target: &QuotaTarget, credential: &Credential) -> Option<Credential> {
    credential.refresh_token.as_ref()?;
    let key = hex::encode(Sha256::digest(target.id.as_bytes()));
    let lock_path = data_dir().join("locks").join(format!("{}.lock", &key[..16]));
    let lock = acquire_file_lock(&lock_path, LOCK_STALE_MS, 0).ok().flatten()?;
    let result = tools::renew_credential(target.tool, &target.config_dir, credential).ok().flatten();
    drop(lock);
    result
}

fn fetch_one(target: &QuotaTarget, cached: Option<&QuotaSnapshot>, now: i64, allow_renew: bool) -> (QuotaSnapshot, Option<i64>) {
    let Some(mut credential) = tools::read_credential(target.tool, &target.config_dir) else {
        return (degraded("missing", cached, now), None);
    };
    let mut renewed = false;
    let mut try_renew = |credential: &mut Credential| -> bool {
        if !allow_renew || renewed {
            return false;
        }
        renewed = true;
        match renew(target, credential) {
            Some(next) => {
                *credential = next;
                true
            }
            None => false,
        }
    };
    if credential.expires_at.is_some_and(|e| e <= now + RENEW_MARGIN_MS) && !try_renew(&mut credential) {
        return (degraded("expired", cached, now), None);
    }
    loop {
        match tools::fetch_quota(target.tool, &credential) {
            Ok(Some(windows)) => return (QuotaSnapshot { windows, state: "ok".into(), fetched_at: now }, None),
            Ok(None) => return (degraded("error", cached, now), None),
            Err(error) => match error.downcast_ref::<HttpError>() {
                Some(e) if e.status == 401 || e.status == 403 => {
                    if try_renew(&mut credential) {
                        continue;
                    }
                    return (degraded("expired", cached, now), None);
                }
                Some(e) if e.status == 429 => {
                    return (degraded("cooldown", cached, now), Some(cooldown_until(e.retry_after.as_deref(), now)));
                }
                _ => return (degraded("error", cached, now), None),
            },
        }
    }
}

/// Quota for every target, from the cache where it is fresh and the network otherwise. Never
/// fails: a profile that cannot be read comes back with a failure state.
pub fn collect_quotas(targets: Vec<QuotaTarget>, refresh: bool, allow_renew: bool) -> HashMap<String, QuotaSnapshot> {
    let mut result = HashMap::new();
    if targets.is_empty() {
        return result;
    }
    let now = now_ms();
    let mut cache = read_cache();
    let mut pending = Vec::new();
    for target in targets {
        let cached = cached_snapshot(&cache, &target.id);
        if let Some(c) = &cached {
            let age = now - c.fetched_at;
            if !refresh && (0..QUOTA_FRESH_MS).contains(&age) {
                result.insert(target.id.clone(), c.clone());
                continue;
            }
        }
        if cache.cooldowns.get(target.tool.name()).copied().unwrap_or(0) > now {
            result.insert(target.id.clone(), degraded("cooldown", cached.as_ref(), now));
            continue;
        }
        pending.push((target, cached));
    }
    if pending.is_empty() {
        return result;
    }
    let settled: Vec<(String, Tool, QuotaSnapshot, Option<i64>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = pending
            .iter()
            .map(|(target, cached)| {
                scope.spawn(move || {
                    let (snap, cooldown) = fetch_one(target, cached.as_ref(), now, allow_renew);
                    (target.id.clone(), target.tool, snap, cooldown)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    for (id, tool, snapshot, cooldown) in settled {
        if let Ok(v) = serde_json::to_value(&snapshot) {
            cache.profiles.insert(id.clone(), v);
        }
        if let Some(until) = cooldown {
            // One 429 pauses the whole tool: the limit is per-IP, not per-account.
            let entry = cache.cooldowns.entry(tool.name().to_string()).or_insert(0);
            *entry = (*entry).max(until);
        }
        result.insert(id, snapshot);
    }
    if let Ok(v) = serde_json::to_value(&cache) {
        let _ = write_json(&cache_path(), &v, None);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_claude() {
        let raw = serde_json::json!({
            "five_hour": { "utilization": 6.0, "resets_at": "2026-10-11T12:00:00+00:00" },
            "seven_day": { "utilization": 46.4, "resets_at": null },
            "seven_day_opus": null,
        });
        let w = parse_claude_quota(&raw).unwrap();
        assert_eq!(w.session.unwrap().resets_at.as_deref(), Some("2026-10-11T12:00:00.000Z"));
        assert_eq!(w.weekly.unwrap().used_percent, 46.4);
    }

    #[test]
    fn parses_codex() {
        let raw = serde_json::json!({ "rate_limit": {
            "primary_window": { "used_percent": 12, "limit_window_seconds": 18000, "reset_at": 1760000000 },
            "secondary_window": { "used_percent": 40, "limit_window_seconds": 604800 },
        }});
        let w = parse_codex_quota(&raw).unwrap();
        assert_eq!(w.session.unwrap().used_percent, 12.0);
        assert_eq!(w.weekly.unwrap().used_percent, 40.0);
    }
}
