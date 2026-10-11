//! Linking a profile's config dir to the primary's: what is shared, what is set aside into a
//! backup, and how it all comes back out.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Result, bail};
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::registry::load_registry;
use crate::tools::{self, ADD_PENDING_MARKER, is_sqlite_companion, names_shared_entries, should_skip_share};
use crate::types::Tool;
use crate::util::{self, exists, read_json, read_json_object, shown, warn, write_json, write_json_if_changed};

/// The Node version's plugin-sync stamp; never linked from the primary.
pub const PLUGIN_SYNC_STAMP: &str = ".clausona-synced";
const PLUGINS_PATH_FILES: [&str; 2] = ["known_marketplaces.json", "installed_plugins.json"];

pub struct LinkInfo {
    pub is_shared_link: bool,
    pub points_to_source: bool,
    pub target_exists: bool,
}

/// Whether `target` is a link to `source`: a symbolic link that resolves to it, or another
/// name of the same file (a hard link).
pub fn inspect_shared_link(target: &Path, source: &Path) -> LinkInfo {
    let Ok(meta) = fs::symlink_metadata(target) else {
        return LinkInfo { is_shared_link: false, points_to_source: false, target_exists: false };
    };
    if meta.file_type().is_symlink() {
        if let Some(resolved) = util::realpath(target) {
            let source = util::realpath(source).unwrap_or_else(|| source.to_path_buf());
            return LinkInfo { is_shared_link: true, points_to_source: resolved == source, target_exists: true };
        }
        let raw = fs::read_link(target).unwrap_or_default();
        let abs = if raw.is_absolute() { raw } else { target.parent().unwrap_or(Path::new("/")).join(raw) };
        return LinkInfo {
            is_shared_link: true,
            points_to_source: util::resolve(&abs) == util::resolve(source),
            target_exists: false,
        };
    }
    if meta.is_file() {
        let same = fs::metadata(source)
            .map(|s| s.is_file() && meta.ino() != 0 && s.ino() != 0 && s.dev() == meta.dev() && s.ino() == meta.ino())
            .unwrap_or(false);
        return LinkInfo { is_shared_link: same, points_to_source: same, target_exists: true };
    }
    LinkInfo { is_shared_link: false, points_to_source: false, target_exists: true }
}

/// Whether deleting `target` loses nothing: a symbolic link, or one of several names of a file.
pub fn holds_nothing_of_its_own(target: &Path) -> bool {
    match fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => true,
        Ok(m) => m.is_file() && m.nlink() >= 2,
        Err(_) => false,
    }
}

/// Whether `config_dir` is `primary` itself, by where each resolves or by identity.
pub fn is_primary_dir(config_dir: &Path, primary: &Path) -> bool {
    if util::real_or_resolved(config_dir) == util::real_or_resolved(primary) {
        return true;
    }
    same_directory(config_dir, primary)
}

pub fn same_directory(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(x), Ok(y)) if x.ino() != 0 && y.ino() != 0 => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => util::resolve(a) == util::resolve(b),
    }
}

// ─── Backups ────────────────────────────────────────────────────────

/// ISO 8601 with each `:` and `.` made `-`.
fn backup_stamp() -> String {
    util::iso_now().replace([':', '.'], "-")
}

fn stamped_backup() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(.+)\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)(?:-(\d+))?$").unwrap())
}

fn fresh_backup_path(backup_dir: &Path, name: &str) -> Result<PathBuf> {
    fs::create_dir_all(backup_dir)?;
    let stamp = backup_stamp();
    for n in 0.. {
        let candidate = backup_dir.join(if n == 0 { format!("{name}.{stamp}") } else { format!("{name}.{stamp}-{n}") });
        if !exists(&candidate) {
            return Ok(candidate);
        }
    }
    unreachable!()
}

/// Moves `target` into a backup of its own, `<backup_dir>/<name>.<timestamp>`.
pub fn set_aside(target: &Path, backup_dir: &Path, name: &str) -> Result<PathBuf> {
    let backup = fresh_backup_path(backup_dir, name)?;
    util::move_to(target, &backup)?;
    Ok(backup)
}

/// The backups in `backup_dir` by the entry each was set aside from, oldest first.
pub fn backups_by_name(backup_dir: &Path) -> BTreeMap<String, Vec<PathBuf>> {
    let mut entries: Vec<(String, String, String, u64)> = util::read_dir_names(backup_dir)
        .into_iter()
        .map(|entry| match stamped_backup().captures(&entry) {
            Some(c) => {
                let count = c.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
                (entry.clone(), c[1].to_string(), c[2].to_string(), count)
            }
            None => (entry.clone(), entry.clone(), String::new(), 0),
        })
        .collect();
    entries.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.cmp(&b.3)));
    let mut by_name: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for (entry, name, _, _) in entries {
        by_name.entry(name).or_default().push(backup_dir.join(entry));
    }
    by_name
}

/// Whether a backup is only a link to the primary's entry of that name.
fn is_link_to_primary_entry(backup: &Path, primary: &Path, name: &str) -> bool {
    util::is_symlink(backup) && fs::read_link(backup).map(|t| t == primary.join(name)).unwrap_or(false)
}

fn own_backups(copies: &[PathBuf], primary: &Path, name: &str) -> Vec<PathBuf> {
    copies.iter().filter(|c| !is_link_to_primary_entry(c, primary, name)).cloned().collect()
}

fn backup_time(backup: &Path) -> Option<i64> {
    let name = backup.file_name()?.to_string_lossy().into_owned();
    let stamp = stamped_backup().captures(&name)?.get(2)?.as_str().to_string();
    // 2026-01-02T03-04-05-678Z → 2026-01-02T03:04:05.678Z
    let (date, time) = stamp.split_once('T')?;
    let parts: Vec<&str> = time.trim_end_matches('Z').split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let iso = format!("{date}T{}:{}:{}.{}Z", parts[0], parts[1], parts[2], parts[3]);
    Some(chrono::DateTime::parse_from_rfc3339(&iso).ok()?.timestamp_millis())
}

/// Whether two backups were set aside in the same pass.
fn set_aside_together(a: &Path, b: &Path) -> bool {
    match (backup_time(a), backup_time(b)) {
        (Some(x), Some(y)) => (x - y).abs() <= 10_000,
        (None, None) => true,
        _ => false,
    }
}

const SQLITE_COMPANION_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Moves the newest of `own` back to `name`'s empty spot. A SQLite database comes back only
/// with the companions set aside with it; when that cannot be told, nothing comes back.
fn put_back_newest(
    backups: &BTreeMap<String, Vec<PathBuf>>,
    name: &str,
    own: &[PathBuf],
    config_dir: &Path,
    primary: &Path,
    backup_dir: &Path,
) -> Result<bool> {
    let Some(newest) = own.last() else { return Ok(false) };
    let target = config_dir.join(name);
    if !name.ends_with(".sqlite") {
        util::move_to(newest, &target)?;
        return Ok(true);
    }
    let shown_dir = shown(config_dir);
    let set_aside_at = backup_time(newest).or_else(|| util::lmtime_ms(newest)).unwrap_or(0);
    let mut bring: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut in_the_way: Vec<(PathBuf, String)> = Vec::new();
    let mut kept_beside: Vec<String> = Vec::new();
    for suffix in SQLITE_COMPANION_SUFFIXES {
        let companion_name = format!("{name}{suffix}");
        let companion_target = config_dir.join(&companion_name);
        let companions = own_backups(backups.get(&companion_name).map(|v| v.as_slice()).unwrap_or(&[]), primary, &companion_name);
        let with_it = companions.iter().rfind(|c| set_aside_together(c, newest)).cloned();
        if with_it.is_none() && companions.iter().any(|c| !own.iter().any(|copy| set_aside_together(c, copy))) {
            warn(&format!(
                "{name} was not put back into {shown_dir}: a backup of its {suffix} was set aside on its own, and could belong to it or not. The copies are still in {}; Codex starts a new {name} meanwhile.",
                shown(backup_dir)
            ));
            return Ok(false);
        }
        if let Ok(present) = fs::symlink_metadata(&companion_target) {
            let mtime = util::lmtime_ms(&companion_target).unwrap_or(0);
            if with_it.is_some() || present.file_type().is_symlink() || mtime > set_aside_at {
                in_the_way.push((companion_target.clone(), companion_name.clone()));
            } else {
                kept_beside.push(companion_name);
                continue;
            }
        }
        if let Some(w) = with_it {
            bring.push((w, companion_target));
        }
    }
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::new();
    let result: Result<()> = (|| {
        for (at, companion_name) in &in_the_way {
            let to = set_aside(at, backup_dir, companion_name)?;
            done.push((at.clone(), to));
        }
        util::move_to(newest, &target)?;
        done.push((newest.clone(), target.clone()));
        for (from, to) in &bring {
            util::move_to(from, to)?;
            done.push((from.clone(), to.clone()));
        }
        Ok(())
    })();
    if let Err(e) = result {
        for (from, to) in done.iter().rev() {
            let _ = util::move_to(to, from);
        }
        return Err(e);
    }
    for companion in kept_beside {
        warn(&format!(
            "{name} was put back into {shown_dir} beside the {companion} already there, which has not changed since {name} was set aside, so it is taken for that copy's. If Codex reports {name} as damaged, move both aside."
        ));
    }
    Ok(true)
}

fn set_aside_companions(profile_dir: &Path, primary: &Path, name: &str, backup_dir: &Path) -> Result<()> {
    for suffix in SQLITE_COMPANION_SUFFIXES {
        let companion_name = format!("{name}{suffix}");
        let companion = profile_dir.join(&companion_name);
        if !exists(&companion) {
            continue;
        }
        let info = inspect_shared_link(&companion, &primary.join(&companion_name));
        if info.is_shared_link && info.points_to_source && holds_nothing_of_its_own(&companion) {
            util::remove_all(&companion);
            continue;
        }
        set_aside(&companion, backup_dir, &companion_name)?;
    }
    Ok(())
}

/// Links to the primary's entries, holding nothing of their own, that the profile is not to
/// share.
pub fn unshared_links(tool: Tool, profile_dir: &Path, primary: &Path, merge: bool) -> Vec<String> {
    util::read_dir_names(profile_dir)
        .into_iter()
        .filter(|name| should_skip_share(tool, name, merge))
        .filter(|name| {
            let target = profile_dir.join(name);
            let info = inspect_shared_link(&target, &primary.join(name));
            info.is_shared_link && info.points_to_source && holds_nothing_of_its_own(&target)
        })
        .collect()
}

/// What linking a Codex profile and settling it would move that a running Codex has open.
pub fn codex_state_to_move(
    tool: Tool,
    config_dir: &Path,
    primary: &Path,
    backup_dir: &Path,
    merge: bool,
    restore_all: bool,
) -> (Vec<String>, Vec<String>) {
    if !names_shared_entries(tool) {
        return (Vec::new(), Vec::new());
    }
    let unlinked = unshared_links(tool, config_dir, primary, merge);
    let mut moving: HashSet<String> = unlinked.iter().cloned().collect();
    for name in util::read_dir_names(primary) {
        if !name.ends_with(".sqlite") || should_skip_share(tool, &name, merge) {
            continue;
        }
        let target = config_dir.join(&name);
        if exists(&target) && !inspect_shared_link(&target, &primary.join(&name)).points_to_source {
            moving.insert(name);
        }
    }
    if exists(backup_dir) {
        for (name, copies) in backups_by_name(backup_dir) {
            if !restore_all && !unlinked.contains(&name) {
                continue;
            }
            if name == ADD_PENDING_MARKER || is_sqlite_companion(&name) || !should_skip_share(tool, &name, merge) {
                continue;
            }
            if exists(&config_dir.join(&name)) {
                continue;
            }
            if !own_backups(&copies, primary, &name).is_empty() {
                moving.insert(name);
            }
        }
    }
    let mut moving: Vec<String> = moving.into_iter().collect();
    moving.sort();
    (unlinked, moving)
}

/// Refuses, unless `force`, to move files a running Codex has open.
pub fn refuse_while_codex_runs(config_dir: &Path, moving: &[String], retry: &str, force: bool) -> Result<()> {
    if force || moving.is_empty() {
        return Ok(());
    }
    let running = tools::codex_processes_for(config_dir);
    if running.is_empty() {
        return Ok(());
    }
    let shown_dir = shown(config_dir);
    let pids = running.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    bail!(
        "Codex is running in {shown_dir} (pid {pids}), and this would move files it has open: {}. Quit Codex in this profile and stop its app-server daemon with 'CODEX_HOME={shown_dir} codex app-server daemon stop', then run this again. Nothing was changed. To go ahead while it runs: {retry}",
        moving.join(", ")
    )
}

fn restore_unshared_from_backup(
    tool: Tool,
    config_dir: &Path,
    primary: &Path,
    backup_dir: &Path,
    merge: bool,
    only: Option<&[String]>,
) -> Result<()> {
    if !exists(backup_dir) {
        return Ok(());
    }
    let backups = backups_by_name(backup_dir);
    for (name, copies) in &backups {
        if only.is_some_and(|o| !o.contains(name)) {
            continue;
        }
        if name == ADD_PENDING_MARKER || is_sqlite_companion(name) || !should_skip_share(tool, name, merge) {
            continue;
        }
        if exists(&config_dir.join(name)) {
            continue;
        }
        let own = own_backups(copies, primary, name);
        if own.is_empty() {
            continue;
        }
        put_back_newest(&backups, name, &own, config_dir, primary, backup_dir)?;
    }
    Ok(())
}

/// After linking a tool that names the entries it shares: brings back what the profile keeps
/// for itself from the backups, and says which links came back as nothing.
pub fn settle_unshared(
    tool: Tool,
    config_dir: &Path,
    primary: &Path,
    backup_dir: &Path,
    merge: bool,
    unlinked: &[String],
    restore_all: bool,
) -> Result<()> {
    if !names_shared_entries(tool) {
        return Ok(());
    }
    restore_unshared_from_backup(tool, config_dir, primary, backup_dir, merge, if restore_all { None } else { Some(unlinked) })?;
    let shown_dir = shown(config_dir);
    for name in tools::copied_when_unlinked(tool) {
        let target = config_dir.join(name);
        if exists(&target) {
            continue;
        }
        let source = primary.join(name);
        if !fs::metadata(&source).map(|m| m.is_file()).unwrap_or(false) {
            continue;
        }
        if unlinked.iter().any(|u| u == name) {
            fs::copy(&source, &target)?;
            warn(&format!("{name} in {shown_dir} was a link to the primary's, and is now a copy of it, which this profile can change."));
        } else {
            warn(&format!(
                "The primary's {name} is not shared, and {shown_dir} has none of its own: copy it there if this account needs what it sets."
            ));
        }
    }
    for name in unlinked {
        if exists(&config_dir.join(name)) {
            continue;
        }
        warn(&format!(
            "{name} in {shown_dir} was a link to the primary's and is gone, with no backup of this profile's own to put back: Codex starts a new one. The primary's is unchanged."
        ));
    }
    Ok(())
}

/// For a tool that names what it does not share: brings back each skip-set entry the profile
/// no longer has from its newest backup of its own. Copied, so the backup stays.
pub fn restore_skipped_from_backup(tool: Tool, config_dir: &Path, primary: &Path, backup_dir: &Path, merge: bool) -> Result<()> {
    if !exists(backup_dir) {
        return Ok(());
    }
    let backups = backups_by_name(backup_dir);
    for name in tools::shared_skip_set(tool, merge) {
        let target = config_dir.join(name);
        if exists(&target) {
            continue;
        }
        for backup in backups.get(name).map(|v| v.as_slice()).unwrap_or(&[]).iter().rev() {
            if is_link_to_primary_entry(backup, primary, name) {
                continue;
            }
            util::copy_recursive(backup, &target)?;
            break;
        }
    }
    Ok(())
}

/// Links each entry the primary shares into the profile. What stands where a link goes is
/// moved into a backup of its own first; nothing of the profile's is deleted.
pub fn setup_shared_links(tool: Tool, profile_dir: &Path, primary: &Path, merge: bool, backup_dir: &Path) -> Result<usize> {
    if is_primary_dir(profile_dir, primary) {
        bail!(
            "{} is the primary config directory itself, so it has nothing to share: linking it would replace each of its entries with a link to that same entry. Nothing was changed.",
            shown(profile_dir)
        );
    }
    let items = util::read_dir_entries(primary);
    if items.is_empty() && !primary.is_dir() {
        bail!("{} does not exist, so there is nothing to share.", shown(primary));
    }
    let mut linked = 0;
    for (name, ft) in &items {
        let source = primary.join(name);
        let target = profile_dir.join(name);
        if should_skip_share(tool, name, merge) {
            let info = inspect_shared_link(&target, &source);
            if info.is_shared_link && info.points_to_source && holds_nothing_of_its_own(&target) {
                util::remove_all(&target);
            }
            continue;
        }
        let symlink_only = !ft.is_dir() && tools::rewrites_whole(tool, name);
        if exists(&target) {
            let info = inspect_shared_link(&target, &source);
            let hard_linked = symlink_only && info.is_shared_link && !util::is_symlink(&target) && holds_nothing_of_its_own(&target);
            if info.is_shared_link && info.points_to_source && !hard_linked {
                linked += 1;
                continue;
            }
            if hard_linked {
                // A hard link to a file saved whole splits at its next save: made a symbolic one.
                fs::remove_file(&target)?;
            } else {
                set_aside(&target, backup_dir, name)?;
            }
        }
        std::os::unix::fs::symlink(&source, &target)?;
        linked += 1;
        if name.ends_with(".sqlite") {
            set_aside_companions(profile_dir, primary, name, backup_dir)?;
        }
    }

    // A link to a file the primary has since lost, for an entry that is no longer shared.
    let primary_names: HashSet<&String> = items.iter().map(|(n, _)| n).collect();
    for name in util::read_dir_names(profile_dir) {
        if primary_names.contains(&name) || !should_skip_share(tool, &name, merge) {
            continue;
        }
        let target = profile_dir.join(&name);
        let info = inspect_shared_link(&target, &primary.join(&name));
        if info.is_shared_link && info.points_to_source && holds_nothing_of_its_own(&target) {
            util::remove_all(&target);
        }
    }
    // A shared link whose target is gone, for an entry the primary no longer has.
    for name in util::read_dir_names(profile_dir) {
        if primary_names.contains(&name) || should_skip_share(tool, &name, merge) {
            continue;
        }
        let target = profile_dir.join(&name);
        let info = inspect_shared_link(&target, &primary.join(&name));
        if info.is_shared_link && !info.target_exists {
            set_aside(&target, backup_dir, &name)?;
        }
    }
    Ok(linked)
}

// ─── Claude's plugins ───────────────────────────────────────────────

/// A known_marketplaces.json entry under the profile's own plugins/marketplaces - one clm
/// manages, rather than one the user registered from a path of their own.
pub fn is_managed_marketplace(entry: &Value, config_dir: &Path) -> bool {
    match entry.get("installLocation").and_then(|v| v.as_str()) {
        None => true,
        Some(location) => {
            let prefix = format!("{}/", config_dir.join("plugins").join("marketplaces").display());
            location.starts_with(&prefix)
        }
    }
}

fn plugin_path_rewrite(install_path: &str, base: &Path, strip_plugins: bool) -> String {
    match install_path.find("/plugins/") {
        Some(i) => {
            let rest = if strip_plugins { &install_path[i + "/plugins/".len()..] } else { &install_path[i + 1..] };
            base.join(rest).to_string_lossy().into_owned()
        }
        None => install_path.to_string(),
    }
}

/// Rewrites a profile's known_marketplaces.json and installed_plugins.json so every path in
/// them points into its own config dir, and drops what is no longer on disk. Never fails: it
/// runs on the way to starting Claude Code. False when a step did.
pub fn sync_plugins_json(config_dir: &Path, primary: &Path) -> bool {
    let run = || -> Result<()> {
        let known_path = config_dir.join("plugins").join("known_marketplaces.json");
        let known = read_json_object(&known_path);
        let marketplaces_dir = primary.join("plugins").join("marketplaces");
        let on_disk: Vec<String> =
            util::read_dir_entries(&marketplaces_dir).into_iter().filter(|(_, t)| t.is_dir()).map(|(n, _)| n).collect();
        let location = |name: &str| config_dir.join("plugins").join("marketplaces").join(name).to_string_lossy().into_owned();

        let mut synced = Map::new();
        for (name, entry) in &known {
            if !is_managed_marketplace(entry, config_dir) {
                synced.insert(name.clone(), entry.clone());
                continue;
            }
            if !on_disk.contains(name) {
                continue;
            }
            let mut e = entry.as_object().cloned().unwrap_or_default();
            e.insert("installLocation".into(), json!(location(name)));
            synced.insert(name.clone(), Value::Object(e));
        }
        let registry = load_registry().ok().flatten();
        let primary_known = read_json_object(&primary.join("plugins").join("known_marketplaces.json"));
        for name in &on_disk {
            if synced.contains_key(name) {
                continue;
            }
            // The primary's own registration first: it is there even before init has saved a
            // registry to look the other profiles up in.
            let found = primary_known.get(name).cloned().or_else(|| {
                registry.as_ref().and_then(|r| {
                    r.profiles.values().find_map(|p| {
                        read_json_object(&p.dir().join("plugins").join("known_marketplaces.json")).get(name).cloned()
                    })
                })
            });
            if let Some(Value::Object(mut e)) = found {
                e.insert("installLocation".into(), json!(location(name)));
                synced.insert(name.clone(), Value::Object(e));
                continue;
            }
            let mut entry = Map::new();
            let git_config = util::read_text(&marketplaces_dir.join(name).join(".git").join("config")).unwrap_or_default();
            static REMOTE: OnceLock<Regex> = OnceLock::new();
            static GH: OnceLock<Regex> = OnceLock::new();
            let remote = REMOTE.get_or_init(|| Regex::new(r#"\[remote "origin"\][^\[]*url\s*=\s*(.+)"#).unwrap());
            if let Some(c) = remote.captures(&git_config) {
                let url = c[1].trim().to_string();
                let gh = GH.get_or_init(|| Regex::new(r"github\.com[:/](.+?)(?:\.git)?$").unwrap());
                if let Some(g) = gh.captures(&url) {
                    entry.insert("source".into(), json!("github"));
                    entry.insert("repo".into(), json!(g[1].to_string()));
                } else {
                    entry.insert("source".into(), json!("git"));
                    entry.insert("url".into(), json!(url));
                }
            }
            entry.insert("installLocation".into(), json!(location(name)));
            entry.insert("lastUpdated".into(), json!(util::iso_now()));
            synced.insert(name.clone(), Value::Object(entry));
        }
        write_json_if_changed(&known_path, &Value::Object(synced))?;

        let installed_path = config_dir.join("plugins").join("installed_plugins.json");
        let installed = read_json(&installed_path)
            .or_else(|| read_json(&primary.join("plugins").join("installed_plugins.json")))
            .unwrap_or_else(|| json!({ "version": 2, "plugins": {} }));
        let mut plugins = Map::new();
        if let Some(Value::Object(all)) = installed.get("plugins") {
            for (plugin, entries) in all {
                let mut kept = Vec::new();
                for entry in entries.as_array().cloned().unwrap_or_default() {
                    match entry.get("installPath").and_then(|v| v.as_str()) {
                        Some(path) => {
                            if util::realpath(Path::new(path)).is_none() {
                                continue;
                            }
                            let mut e = entry.as_object().cloned().unwrap_or_default();
                            e.insert("installPath".into(), json!(plugin_path_rewrite(path, config_dir, false)));
                            kept.push(Value::Object(e));
                        }
                        None => kept.push(entry),
                    }
                }
                if !kept.is_empty() {
                    plugins.insert(plugin.clone(), Value::Array(kept));
                }
            }
        }
        let version = installed.get("version").cloned().unwrap_or(json!(2));
        write_json_if_changed(&installed_path, &json!({ "version": version, "plugins": plugins }))?;
        Ok(())
    };
    run().is_ok()
}

/// Folds what a profile installed into the primary's plugins/, before the profile's own are
/// replaced by links. Best effort.
pub fn merge_plugin_files(profile_plugins: &Path, primary_plugins: &Path) {
    for (name, ft) in util::read_dir_entries(&profile_plugins.join("marketplaces")) {
        let dst = primary_plugins.join("marketplaces").join(&name);
        if ft.is_dir() && !exists(&dst) {
            let _ = fs::create_dir_all(primary_plugins.join("marketplaces"));
            let _ = util::copy_recursive(&profile_plugins.join("marketplaces").join(&name), &dst);
        }
    }
    for name in util::read_dir_names(&profile_plugins.join("cache")) {
        let dst = primary_plugins.join("cache").join(&name);
        if !exists(&dst) {
            let _ = fs::create_dir_all(primary_plugins.join("cache"));
            let _ = util::copy_recursive(&profile_plugins.join("cache").join(&name), &dst);
        }
    }
    let src_known = read_json_object(&profile_plugins.join("known_marketplaces.json"));
    let dst_known_path = primary_plugins.join("known_marketplaces.json");
    let mut dst_known = read_json_object(&dst_known_path);
    let mut changed = false;
    for (name, entry) in src_known {
        if dst_known.contains_key(&name) {
            continue;
        }
        let mut e = entry.as_object().cloned().unwrap_or_default();
        e.insert("installLocation".into(), json!(primary_plugins.join("marketplaces").join(&name).to_string_lossy()));
        dst_known.insert(name, Value::Object(e));
        changed = true;
    }
    if changed {
        let _ = write_json(&dst_known_path, &Value::Object(dst_known), None);
    }
    let src_installed = read_json(&profile_plugins.join("installed_plugins.json")).unwrap_or(json!({ "plugins": {} }));
    let dst_installed_path = primary_plugins.join("installed_plugins.json");
    let dst_installed = read_json(&dst_installed_path).unwrap_or(json!({ "version": 2, "plugins": {} }));
    let mut dst_plugins = dst_installed.get("plugins").and_then(|p| p.as_object()).cloned().unwrap_or_default();
    let mut changed = false;
    if let Some(Value::Object(src)) = src_installed.get("plugins") {
        for (plugin, entries) in src {
            if dst_plugins.contains_key(plugin) {
                continue;
            }
            let rewritten: Vec<Value> = entries
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|entry| match entry.get("installPath").and_then(|v| v.as_str()) {
                    Some(path) => {
                        let mut e = entry.as_object().cloned().unwrap_or_default();
                        e.insert("installPath".into(), json!(plugin_path_rewrite(path, primary_plugins, true)));
                        Value::Object(e)
                    }
                    None => entry,
                })
                .collect();
            dst_plugins.insert(plugin.clone(), Value::Array(rewritten));
            changed = true;
        }
    }
    if changed {
        let version = dst_installed.get("version").cloned().unwrap_or(json!(2));
        let _ = write_json(&dst_installed_path, &json!({ "version": version, "plugins": dst_plugins }), None);
    }
}

/// Links each entry of the primary's plugins/ into the profile's own plugins/, setting aside
/// what stands in the way into one backup for the run.
pub fn setup_plugins_dir(profile_dir: &Path, primary: &Path, backup_dir: &Path) -> Result<()> {
    if is_primary_dir(profile_dir, primary) {
        bail!("{} is the primary config directory itself. Nothing was changed.", shown(profile_dir));
    }
    let primary_plugins = primary.join("plugins");
    if !exists(&primary_plugins) {
        return Ok(());
    }
    let profile_plugins = profile_dir.join("plugins");
    if util::is_symlink(&profile_plugins) {
        fs::remove_file(&profile_plugins)?;
    }
    fs::create_dir_all(&profile_plugins)?;
    let mut set_aside_dir: Option<PathBuf> = None;
    for (name, _) in util::read_dir_entries(&primary_plugins) {
        if PLUGINS_PATH_FILES.contains(&name.as_str()) || name.starts_with(PLUGIN_SYNC_STAMP) {
            continue;
        }
        let source = primary_plugins.join(&name);
        let target = profile_plugins.join(&name);
        if exists(&target) {
            let info = inspect_shared_link(&target, &source);
            if info.is_shared_link && info.points_to_source {
                continue;
            }
            if set_aside_dir.is_none() {
                let dir = fresh_backup_path(backup_dir, "plugins")?;
                fs::create_dir(&dir)?;
                for f in PLUGINS_PATH_FILES {
                    let _ = fs::copy(profile_plugins.join(f), dir.join(f));
                }
                set_aside_dir = Some(dir);
            }
            util::move_to(&target, &set_aside_dir.as_ref().unwrap().join(&name))?;
        }
        std::os::unix::fs::symlink(&source, &target)?;
    }
    sync_plugins_json(profile_dir, primary);
    Ok(())
}

// ─── Sessions ───────────────────────────────────────────────────────

/// Folds a profile's own session state into the primary ahead of linking it: transcripts per
/// project slug, and background-session and team records.
pub fn merge_session_state(source_dir: &Path, primary: &Path) {
    let src_projects = source_dir.join("projects");
    let dst_projects = primary.join("projects");
    if util::is_real_dir(&src_projects) && exists(&dst_projects) {
        for (slug, ft) in util::read_dir_entries(&src_projects) {
            if !ft.is_dir() {
                continue;
            }
            let dst_slug = dst_projects.join(&slug);
            let _ = fs::create_dir_all(&dst_slug);
            for item in util::read_dir_names(&src_projects.join(&slug)) {
                if item == "sessions-index.json" {
                    continue;
                }
                let dst = dst_slug.join(&item);
                if exists(&dst) {
                    continue;
                }
                if let Err(e) = util::copy_recursive(&src_projects.join(&slug).join(&item), &dst) {
                    warn(&format!("mergeSessionFiles: could not copy {item}: {e}"));
                }
            }
            let _ = fs::remove_file(dst_slug.join("sessions-index.json"));
        }
    }
    for kind in ["jobs", "teams"] {
        let src = source_dir.join(kind);
        let dst = primary.join(kind);
        if !util::is_real_dir(&src) || !exists(&dst) {
            continue;
        }
        for (name, ft) in util::read_dir_entries(&src) {
            if !ft.is_dir() {
                continue;
            }
            let target = dst.join(&name);
            if exists(&target) {
                continue;
            }
            if let Err(e) = util::copy_recursive(&src.join(&name), &target) {
                warn(&format!("mergeRecordDirs({kind}): could not copy {name}: {e}"));
                continue;
            }
            if kind == "jobs" {
                let state_path = target.join("state.json");
                let mut state = read_json_object(&state_path);
                if let Some(recorded) = state.get("linkScanPath").and_then(|v| v.as_str()).map(String::from) {
                    let prefix = format!("{}/", source_dir.display().to_string().trim_end_matches('/'));
                    if let Some(rest) = recorded.strip_prefix(&prefix) {
                        state.insert("linkScanPath".into(), json!(primary.join(rest).to_string_lossy()));
                        let _ = write_json(&state_path, &Value::Object(state), None);
                    }
                }
            }
        }
    }
}

// ─── Undoing a profile ──────────────────────────────────────────────

/// Strips a profile's links to the primary and puts back what clm set aside from it,
/// wherever the profile has none of that entry. What cannot go back stays in the backup.
pub fn cleanup_profile(tool: Tool, name: &str, profile_id: &str, config_dir: &Path, primary: &Path, owns_key: bool, keep_backup: bool) -> Result<()> {
    let backup_dir = crate::registry::backup_dir_for(tool, name)?;
    match fs::remove_file(config_dir.join(ADD_PENDING_MARKER)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR) => {}
        Err(e) => return Err(e.into()),
    }
    if owns_key {
        let _ = crate::secrets::delete_secret(profile_id);
    }
    if is_primary_dir(config_dir, primary) {
        return Ok(());
    }
    let profile_plugins = config_dir.join("plugins");
    if util::is_real_dir(&profile_plugins) {
        for entry in util::read_dir_names(&profile_plugins) {
            let p = profile_plugins.join(&entry);
            let info = inspect_shared_link(&p, &primary.join("plugins").join(&entry));
            if info.is_shared_link && holds_nothing_of_its_own(&p) {
                util::remove_all(&p);
            }
        }
    }
    for entry in util::read_dir_names(config_dir) {
        let p = config_dir.join(&entry);
        let info = inspect_shared_link(&p, &primary.join(&entry));
        if info.is_shared_link && holds_nothing_of_its_own(&p) {
            util::remove_all(&p);
        }
    }
    if keep_backup || !exists(&backup_dir) {
        return Ok(());
    }
    if !exists(config_dir) {
        if util::dir_occupied(&backup_dir) {
            warn(&format!(
                "{} no longer exists, so nothing was restored into it. What clm set aside from it is still in {}: move it somewhere else, or delete it once nothing in it is needed.",
                shown(config_dir),
                shown(&backup_dir)
            ));
        } else {
            let _ = fs::remove_dir(&backup_dir);
        }
        return Ok(());
    }
    let mut not_put_back: Vec<String> = Vec::new();
    let backups = backups_by_name(&backup_dir);
    for (item, copies) in &backups {
        let target = config_dir.join(item);
        let mut own = Vec::new();
        for copy in copies {
            if is_link_to_primary_entry(copy, primary, item) {
                let _ = fs::remove_file(copy);
            } else {
                own.push(copy.clone());
            }
        }
        let Some(newest) = own.last().cloned() else { continue };
        if is_sqlite_companion(item) {
            continue;
        }
        if !exists(&target) {
            put_back_newest(&backups, item, &own, config_dir, primary, &backup_dir)?;
            continue;
        }
        if item == "plugins" && util::is_real_dir(&target) && util::is_real_dir(&newest) {
            for inner in util::read_dir_names(&newest) {
                let inner_target = target.join(&inner);
                if exists(&inner_target) {
                    not_put_back.push(format!("plugins/{inner}"));
                    continue;
                }
                util::move_to(&newest.join(&inner), &inner_target)?;
            }
            let _ = fs::remove_dir(&newest);
            continue;
        }
        not_put_back.push(item.clone());
    }
    if util::dir_occupied(&backup_dir) {
        not_put_back.sort();
        let shown_dir = shown(config_dir);
        let kept = if not_put_back.is_empty() {
            String::new()
        } else {
            format!(
                " {shown_dir} has its own {} again, newer than any backup, so {} not put back.",
                not_put_back.join(", "),
                if not_put_back.len() == 1 { "that was" } else { "those were" }
            )
        };
        warn(&format!(
            "{shown_dir} has the newest backup of each entry it was missing back.{kept} What clm set aside and did not put back is still in {}: move it somewhere else, or delete it once nothing in it is needed.",
            shown(&backup_dir)
        ));
    } else {
        let _ = fs::remove_dir(&backup_dir);
    }
    Ok(())
}
