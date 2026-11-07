//! `clm sessions`: the Claude desktop app's Code-tab sessions, listed for the CLI and resumed
//! there. The app runs Claude Code itself and keeps each session's transcript where the CLI
//! keeps its own (`<config>/projects/<folder>/<id>.jsonl`), so `claude --resume <id>` opens one
//! from the session's folder. What the app adds is its own index of titles and folders, which
//! is all this module reads; it never writes to the app's files.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, anyhow, bail};
use chrono::{Local, TimeZone};
use serde_json::{Value, json};

use crate::format::terminal_width;
use crate::registry::{claude_json_path, load_registry, parse_profile_ref};
use crate::service;
use crate::style::*;
use crate::tools;
use crate::types::{Registry, Tool};
use crate::usage;
use crate::util::{self, home, now_ms, read_json, realpath, shown_str};

const DEFAULT_LIMIT: usize = 20;

/// One Code-tab session as the app indexes it.
#[derive(Clone, Debug)]
pub struct DesktopSession {
    /// The app's own id, `local_<uuid>`.
    pub desktop_id: String,
    /// Claude Code's session id: the transcript's file name and what `--resume` takes.
    pub id: String,
    pub title: String,
    pub cwd: String,
    pub origin_cwd: Option<String>,
    pub branch: Option<String>,
    pub model: Option<String>,
    pub created_at: i64,
    pub last_activity_at: i64,
    pub archived: bool,
    /// The account the app ran it under (its directory name in the app's index).
    pub account_uuid: String,
    /// Where the transcript is, when it is still on disk. Claude Code deletes transcripts
    /// older than `cleanupPeriodDays` (30 days by default), and the app's index outlives them.
    pub transcript: Option<PathBuf>,
    /// A Claude Code process has it open: in the app, or a CLI `--resume` of it.
    pub running: bool,
}

impl DesktopSession {
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(8)]
    }

    /// The folder `claude --resume` has to start in: the session's own, else the one it
    /// was started from (a worktree the app has since removed).
    fn launch_dir(&self) -> Option<PathBuf> {
        [Some(self.cwd.as_str()), self.origin_cwd.as_deref()].into_iter().flatten().map(PathBuf::from).find(|p| p.is_dir())
    }

    fn to_json(&self, profiles: &[String], account_profile: Option<&str>) -> Value {
        json!({
            "id": self.id,
            "desktopId": self.desktop_id,
            "title": self.title,
            "cwd": self.cwd,
            "originCwd": self.origin_cwd,
            "branch": self.branch,
            "model": self.model,
            "createdAt": iso(self.created_at),
            "lastActivityAt": iso(self.last_activity_at),
            "archived": self.archived,
            "running": self.running,
            "transcript": self.transcript.as_ref().map(|p| p.to_string_lossy().into_owned()),
            "accountProfile": account_profile,
            "profiles": profiles,
        })
    }
}

/// The app's data directory: `CLM_CLAUDE_DESKTOP_DIR`, else where the app keeps it.
pub fn desktop_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CLM_CLAUDE_DESKTOP_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    if cfg!(target_os = "macos") {
        return home().join("Library/Application Support/Claude");
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("Claude")
}

/// How Claude Code names a project's folder under `projects/`: every character that is
/// not an ASCII letter or digit becomes `-`.
pub fn project_slug(cwd: &str) -> String {
    cwd.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Every Claude config directory a transcript could be in, each `projects` folder once:
/// registered profiles share theirs through a link when they merge sessions.
fn config_dirs(registry: Option<&Registry>) -> Vec<(PathBuf, Vec<String>)> {
    let mut dirs: Vec<(PathBuf, Option<String>)> = Vec::new();
    if let Some(r) = registry {
        for (id, p) in &r.profiles {
            if p.tool() == Tool::Claude {
                dirs.push((p.dir(), Some(id.clone())));
            }
        }
    }
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR").filter(|d| !d.is_empty()) {
        dirs.push((PathBuf::from(dir), None));
    }
    dirs.push((tools::default_config_dir(Tool::Claude), None));

    let mut out: Vec<(PathBuf, Vec<String>)> = Vec::new();
    let mut index: HashMap<PathBuf, usize> = HashMap::new();
    for (dir, id) in dirs {
        let projects = dir.join("projects");
        let Some(real) = realpath(&projects) else { continue };
        let i = *index.entry(real.clone()).or_insert_with(|| {
            out.push((real, Vec::new()));
            out.len() - 1
        });
        if let Some(id) = id
            && !out[i].1.contains(&id) {
                out[i].1.push(id);
            }
    }
    out
}

fn find_transcript(projects_dirs: &[(PathBuf, Vec<String>)], cwd: &str, id: &str) -> Option<PathBuf> {
    let file = format!("{id}.jsonl");
    let slug = project_slug(cwd);
    for (projects, _) in projects_dirs {
        let p = projects.join(&slug).join(&file);
        if p.is_file() {
            return Some(p);
        }
    }
    // Long paths get a shortened folder name; look in every project for the file itself.
    for (projects, _) in projects_dirs {
        for name in util::read_dir_names(projects) {
            let p = projects.join(name).join(&file);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// The profiles whose `projects` folder holds `transcript`.
fn profiles_seeing(projects_dirs: &[(PathBuf, Vec<String>)], transcript: &Path) -> Vec<String> {
    projects_dirs.iter().filter(|(p, _)| transcript.starts_with(p)).flat_map(|(_, ids)| ids.clone()).collect()
}

/// Account uuid → registered profile, read from each profile's `.claude.json`.
fn account_profiles(registry: Option<&Registry>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(r) = registry else { return out };
    for (id, p) in &r.profiles {
        if p.tool() != Tool::Claude {
            continue;
        }
        let uuid = read_json(&claude_json_path(&home(), &p.dir()))
            .and_then(|v| v.get("oauthAccount")?.get("accountUuid")?.as_str().map(String::from));
        if let Some(uuid) = uuid {
            out.entry(uuid).or_insert_with(|| id.clone());
        }
    }
    out
}

/// Environment and arguments of every running Claude Code process, as one string each.
fn claude_process_texts() -> Vec<String> {
    let me = std::process::id();
    if cfg!(target_os = "linux") {
        let mut out = Vec::new();
        for name in util::read_dir_names(Path::new("/proc")) {
            let Ok(pid) = name.parse::<u32>() else { continue };
            if pid == me {
                continue;
            }
            let base = Path::new("/proc").join(&name);
            let Ok(cmdline) = std::fs::read(base.join("cmdline")) else { continue };
            let args = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            if !names_claude(args.split(' ').next().unwrap_or("")) && !args.contains("/claude ") {
                continue;
            }
            let environ = std::fs::read(base.join("environ")).map(|e| String::from_utf8_lossy(&e).replace('\0', " ")).unwrap_or_default();
            out.push(format!("{args} {environ}"));
        }
        return out;
    }
    let Ok(out) = Command::new("ps").args(["-axo", "pid=,comm="]).output() else { return Vec::new() };
    let pids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let (pid, comm) = l.split_once(' ')?;
            (names_claude(comm.trim()) && pid.parse::<u32>().ok()? != me).then(|| pid.to_string())
        })
        .collect();
    if pids.is_empty() {
        return Vec::new();
    }
    let Ok(out) = Command::new("ps").args(["-Eww", "-o", "command=", "-p", &pids.join(",")]).output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect()
}

fn names_claude(path: &str) -> bool {
    Path::new(path).file_name().is_some_and(|n| n == "claude")
}

/// Whether a process holds the session: the app starts it with the session's own id in
/// `CLAUDE_CODE_HOST_SESSION_ID`; a CLI holds it by `--resume <id>` or `--session-id <id>`.
fn holds(text: &str, desktop_id: &str, id: &str) -> bool {
    let words: Vec<&str> = text.split_whitespace().collect();
    words.iter().any(|w| w.strip_prefix("CLAUDE_CODE_HOST_SESSION_ID=") == Some(desktop_id))
        || words.windows(2).any(|w| matches!(w[0], "--resume" | "-r" | "--session-id") && w[1] == id)
        || words.iter().any(|w| w.strip_prefix("--resume=").or_else(|| w.strip_prefix("--session-id=")) == Some(id))
}

/// Every session in the app's index, newest activity first.
pub fn load_sessions(registry: Option<&Registry>) -> Vec<DesktopSession> {
    let root = desktop_dir().join("claude-code-sessions");
    let projects_dirs = config_dirs(registry);
    let processes = claude_process_texts();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for account in util::read_dir_names(&root) {
        for org in util::read_dir_names(&root.join(&account)) {
            let dir = root.join(&account).join(&org);
            for name in util::read_dir_names(&dir) {
                if !name.starts_with("local_") || !name.ends_with(".json") {
                    continue;
                }
                let Some(v) = read_json(&dir.join(&name)) else { continue };
                let s = |k: &str| v.get(k).and_then(|x| x.as_str()).filter(|x| !x.is_empty()).map(String::from);
                let n = |k: &str| v.get(k).and_then(|x| x.as_i64());
                let (Some(id), Some(cwd)) = (s("cliSessionId"), s("cwd")) else { continue };
                let desktop_id = s("sessionId").unwrap_or_else(|| name.trim_end_matches(".json").to_string());
                if !seen.insert(desktop_id.clone()) {
                    continue;
                }
                let created_at = n("createdAt").unwrap_or(0);
                let transcript = find_transcript(&projects_dirs, &cwd, &id);
                let running = processes.iter().any(|t| holds(t, &desktop_id, &id));
                out.push(DesktopSession {
                    title: s("title").map(|t| one_line(&t)).unwrap_or_default(),
                    origin_cwd: s("originCwd").filter(|o| *o != cwd),
                    branch: s("branch"),
                    model: s("model"),
                    created_at,
                    last_activity_at: n("lastActivityAt").unwrap_or(created_at).max(created_at),
                    archived: v.get("isArchived").and_then(|x| x.as_bool()).unwrap_or(false),
                    account_uuid: account.clone(),
                    transcript,
                    running,
                    desktop_id,
                    id,
                    cwd,
                });
            }
        }
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.last_activity_at));
    out
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn iso(ms: i64) -> Option<String> {
    (ms > 0).then(|| Local.timestamp_millis_opt(ms).single().map(|t| t.to_rfc3339()))?
}

fn ago(ms: i64) -> String {
    if ms <= 0 {
        return "—".into();
    }
    let s = (now_ms() - ms).max(0) / 1000;
    match s {
        0..60 => "now".into(),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        86400..2_592_000 => format!("{}d", s / 86400),
        _ => Local.timestamp_millis_opt(ms).single().map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_default(),
    }
}

/// Terminal columns a character takes: two for East Asian wide characters and emoji.
fn char_width(c: char) -> usize {
    let c = c as u32;
    let wide = matches!(c,
        0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE4F | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6 | 0x1F300..=0x1F64F | 0x1F900..=0x1F9FF | 0x20000..=0x3FFFD);
    if wide { 2 } else { 1 }
}

fn fit(s: &str, width: usize) -> String {
    let total: usize = s.chars().map(char_width).sum();
    if total <= width {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = char_width(c);
        if used + w + 1 > width {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// A folder for display: `~` for home, and its tail kept when it is cut.
fn fit_path(p: &str, width: usize) -> String {
    let s = shown_str(p);
    let n = s.chars().count();
    if n <= width {
        return s;
    }
    let tail: String = s.chars().skip(n - (width - 1)).collect();
    format!("…{tail}")
}

pub struct ListOptions {
    pub query: Option<String>,
    pub here: bool,
    pub all: bool,
    pub limit: Option<usize>,
}

fn matches_query(s: &DesktopSession, q: &str) -> bool {
    let q = q.to_lowercase();
    s.id.starts_with(&q) || s.desktop_id.to_lowercase().contains(&q) || s.title.to_lowercase().contains(&q) || s.cwd.to_lowercase().contains(&q)
}

fn in_current_dir(s: &DesktopSession) -> bool {
    let Some(here) = std::env::current_dir().ok().and_then(|d| realpath(&d)) else { return false };
    [Some(s.cwd.as_str()), s.origin_cwd.as_deref()]
        .into_iter()
        .flatten()
        .any(|p| util::is_within(&here, &util::real_or_resolved(Path::new(p))))
}

pub fn cmd_list(opts: &ListOptions, json_out: bool) -> Result<String> {
    let registry = load_registry().ok().flatten();
    let root = desktop_dir().join("claude-code-sessions");
    if !root.is_dir() {
        bail!("No Claude desktop sessions found: {} does not exist.\nSet CLM_CLAUDE_DESKTOP_DIR if the app keeps its data elsewhere.", shown_str(&root.to_string_lossy()));
    }
    let all = load_sessions(registry.as_ref());
    let total = all.len();
    let mut hidden_gone = 0;
    let mut hidden_archived = 0;
    let mut shown: Vec<DesktopSession> = Vec::new();
    for s in all {
        if opts.query.as_deref().is_some_and(|q| !matches_query(&s, q)) || (opts.here && !in_current_dir(&s)) {
            continue;
        }
        if !opts.all && s.archived {
            hidden_archived += 1;
            continue;
        }
        if !opts.all && s.transcript.is_none() {
            hidden_gone += 1;
            continue;
        }
        shown.push(s);
    }
    let matched = shown.len();
    let limit = opts.limit.or(if json_out { None } else { Some(DEFAULT_LIMIT) }).filter(|l| *l > 0);
    if let Some(l) = limit {
        shown.truncate(l);
    }

    let projects_dirs = config_dirs(registry.as_ref());
    let accounts = account_profiles(registry.as_ref());
    if json_out {
        let items: Vec<Value> = shown
            .iter()
            .map(|s| {
                let seeing = s.transcript.as_ref().map(|t| profiles_seeing(&projects_dirs, t)).unwrap_or_default();
                s.to_json(&seeing, accounts.get(&s.account_uuid).map(String::as_str))
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&Value::Array(items))?);
    }

    if shown.is_empty() {
        let what = if total == 0 { "The Claude app has no Code-tab sessions on this computer." } else { "No sessions match." };
        let mut out = vec![format!("  {}", dim(what))];
        if hidden_gone + hidden_archived > 0 {
            out.push(format!("  {}", dim(&format!("{} archived or no longer on disk; --all shows them.", hidden_gone + hidden_archived))));
        }
        return Ok(out.join("\n"));
    }

    let id_w = 10;
    let age_w = 12;
    let width = terminal_width().max(60);
    let rest = width.saturating_sub(4 + id_w + age_w);
    let folder_w = (rest * 2 / 5).clamp(16, 40);
    let title_w = rest.saturating_sub(folder_w + 2).max(10);
    let mut rows = vec![
        format!(
            "    {}{}{}{}",
            secondary(&pad_plain("ID", id_w)),
            secondary(&pad_plain("ACTIVE", age_w)),
            secondary(&pad_plain("FOLDER", folder_w + 2)),
            secondary("TITLE")
        ),
        format!("    {}", dimmer(&"─".repeat((id_w + age_w + folder_w + 2 + title_w).min(width.saturating_sub(4))))),
    ];
    for s in &shown {
        let marker = if s.running { green("●") } else { " ".into() };
        let age = if s.running { "open".to_string() } else { ago(s.last_activity_at) };
        let mut tags = Vec::new();
        if s.archived {
            tags.push("archived");
        }
        if s.transcript.is_none() {
            tags.push("gone");
        }
        let tag = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
        let title = if s.title.is_empty() { "(untitled)" } else { s.title.as_str() };
        let title_cell = fit(&format!("{title}{tag}"), title_w);
        let unusable = s.transcript.is_none();
        rows.push(format!(
            "  {marker} {}{}{}{}",
            if unusable { dim(&pad_plain(s.short_id(), id_w)) } else { accent(&pad_plain(s.short_id(), id_w)) },
            dim(&pad_plain(&age, age_w)),
            secondary(&pad_plain(&fit_path(&s.cwd, folder_w), folder_w + 2)),
            if unusable { dim(&title_cell) } else { title_cell }
        ));
    }
    rows.push(String::new());
    let mut notes = Vec::new();
    if matched > shown.len() {
        notes.push(format!("{} of {matched} shown; --limit 0 shows every one", shown.len()));
    }
    if hidden_gone + hidden_archived > 0 {
        notes.push(format!("{} archived or no longer on disk hidden; --all shows them", hidden_gone + hidden_archived));
    }
    for n in notes {
        rows.push(format!("  {}", dim(&n)));
    }
    rows.push(format!("  {} {}", dim("Continue one in this terminal:"), accent("clm sessions resume <id>")));
    Ok(rows.join("\n"))
}

/// The one session `input` names: a session id or its prefix, or the app's `local_` id.
fn pick<'a>(sessions: &'a [DesktopSession], input: &str) -> Result<&'a DesktopSession> {
    let q = input.trim().to_lowercase();
    if q.len() < 4 {
        bail!("Give at least the first 4 characters of the session's id (from `clm sessions`).");
    }
    let found: Vec<&DesktopSession> = sessions
        .iter()
        .filter(|s| s.id.starts_with(&q) || s.desktop_id.to_lowercase() == q || s.desktop_id.to_lowercase().strip_prefix("local_").is_some_and(|d| d.starts_with(&q)))
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => bail!("No desktop session has the id {input}. Run `clm sessions` to list them."),
        many => {
            let listed: String = many.iter().take(8).map(|s| format!("\n    {}  {}", accent(&s.id), s.title)).collect();
            bail!("{input} matches {} sessions; give more of the id:{listed}", many.len())
        }
    }
}

pub struct ResumeOptions {
    pub session: String,
    pub profile: Option<String>,
    pub fork: bool,
    pub claude_args: Vec<String>,
}

/// Starts `claude --resume <id>` in the session's folder, under a profile that can see its
/// transcript. Returns claude's exit code.
pub fn resume(opts: &ResumeOptions) -> Result<i32> {
    let registry = load_registry().ok().flatten();
    let sessions = load_sessions(registry.as_ref());
    let s = pick(&sessions, &opts.session)?;
    let label = if s.title.is_empty() { s.short_id().to_string() } else { format!("“{}”", s.title) };
    let Some(transcript) = &s.transcript else {
        bail!(
            "The transcript of {label} is no longer on disk, so there is nothing to resume.\n    Claude Code deletes transcripts older than cleanupPeriodDays (30 days unless settings.json says otherwise)."
        );
    };
    if s.running && !opts.fork {
        bail!(
            "{label} is open in Claude right now, and two processes writing one transcript corrupt it.\n    Stop it in the app first, or continue in a copy: {}",
            accent(&format!("clm sessions resume {} --fork", s.short_id()))
        );
    }
    let Some(dir) = s.launch_dir() else {
        bail!("{label} ran in {}, which no longer exists. Claude Code finds a session from its folder, so recreate the folder first.", shown_str(&s.cwd));
    };

    let projects_dirs = config_dirs(registry.as_ref());
    let seeing = profiles_seeing(&projects_dirs, transcript);
    let accounts = account_profiles(registry.as_ref());
    let profile = match (&opts.profile, &registry) {
        (Some(input), Some(r)) => {
            let id = parse_profile_ref(input, r)?.id;
            if !seeing.contains(&id) {
                bail!(
                    "{id} keeps its own session history, so it cannot see this session.\n    {}",
                    if seeing.is_empty() { "No registered profile can.".to_string() } else { format!("Profiles that can: {}", seeing.join(", ")) }
                );
            }
            Some(id)
        }
        (Some(_), None) => bail!("--profile needs clm set up: run `clm init` first."),
        (None, Some(r)) => {
            let active = r.active(Tool::Claude).filter(|a| seeing.contains(a)).cloned();
            let own = accounts.get(&s.account_uuid).filter(|a| seeing.contains(a)).cloned();
            active.or(own).or_else(|| seeing.first().cloned())
        }
        (None, None) => None,
    };

    let mut args = vec!["--resume".to_string(), s.id.clone()];
    if opts.fork {
        args.push("--fork-session".into());
    }
    args.extend(opts.claude_args.iter().cloned());

    let mut cmd = Command::new(tools::binary(Tool::Claude));
    cmd.args(&args).current_dir(&dir);
    match &profile {
        Some(id) => {
            let (_, env, unset) = service::resolve_profile_env(id)?;
            for k in &unset {
                cmd.env_remove(k);
            }
            for (k, v) in &env {
                cmd.env(k, v);
            }
        }
        None => {
            // No profile sees it: run with the config directory that holds it.
            let config = transcript.parent().and_then(Path::parent).and_then(Path::parent).map(Path::to_path_buf);
            let default = realpath(&tools::default_config_dir(Tool::Claude));
            if let Some(config) = config.filter(|c| realpath(c) != default) {
                cmd.env("CLAUDE_CONFIG_DIR", config);
            } else {
                cmd.env_remove("CLAUDE_CONFIG_DIR");
            }
        }
    }
    // Inside a desktop session these name that session; the resumed one is not it.
    for k in ["CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_HOST_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT"] {
        cmd.env_remove(k);
    }

    let who = profile.as_deref().map(|p| format!(" as {}", bold(p))).unwrap_or_default();
    let how = if opts.fork { "Forking" } else { "Resuming" };
    eprintln!("  {} {how} {label} in {}{who}", accent("▸"), dim(&shown_str(&dir.to_string_lossy())));
    let status = cmd.status().map_err(|e| anyhow!("could not start {}: {e}", tools::binary(Tool::Claude)))?;
    if let Some(id) = &profile {
        usage::track_usage(Some(id));
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_matches_claude_code() {
        assert_eq!(project_slug("/Volumes/PS3/DevResearch/clm"), "-Volumes-PS3-DevResearch-clm");
        assert_eq!(project_slug("/Users/me/.claude-work/x_y"), "-Users-me--claude-work-x-y");
    }

    #[test]
    fn holds_by_host_id_or_resume_flag() {
        let app = "/x/claude --output-format stream-json CLAUDE_CODE_HOST_SESSION_ID=local_abc HOME=/u";
        assert!(holds(app, "local_abc", "123"));
        assert!(!holds(app, "local_abcd", "123"));
        assert!(holds("/bin/claude --resume 123 -p", "local_z", "123"));
        assert!(holds("/bin/claude --resume=123", "local_z", "123"));
        assert!(!holds("/bin/claude --resume 1234", "local_z", "123"));
    }

    #[test]
    fn fit_counts_wide_characters() {
        assert_eq!(fit("导入桌面版", 10), "导入桌面版");
        assert_eq!(fit("导入桌面版 session", 9), "导入桌面…");
        assert_eq!(fit("abc", 3), "abc");
        assert_eq!(fit("abcd", 3), "ab…");
    }

    fn session(id: &str, desktop: &str) -> DesktopSession {
        DesktopSession {
            desktop_id: desktop.into(),
            id: id.into(),
            title: String::new(),
            cwd: "/".into(),
            origin_cwd: None,
            branch: None,
            model: None,
            created_at: 0,
            last_activity_at: 0,
            archived: false,
            account_uuid: String::new(),
            transcript: None,
            running: false,
        }
    }

    #[test]
    fn pick_by_prefix() {
        let list = vec![session("abcd1111", "local_ffff0000"), session("abcd2222", "local_eeee0000")];
        assert_eq!(pick(&list, "abcd1").unwrap().id, "abcd1111");
        assert_eq!(pick(&list, "ffff").unwrap().id, "abcd1111");
        assert_eq!(pick(&list, "local_eeee0000").unwrap().id, "abcd2222");
        assert!(pick(&list, "abcd").is_err());
        assert!(pick(&list, "abc").is_err());
        assert!(pick(&list, "9999").is_err());
    }
}
