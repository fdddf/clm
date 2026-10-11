//! Every operation on profiles: what each command does, apart from how it is printed.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::checks::{
    self, BaseUrlProblem, carries_credential_token, check_base_url, has_bare_userinfo, key_source_phrase, origin_of,
    redact_base_url, sends_key_in_clear, shares_secret_source, url_host, url_hostname,
};
use crate::env::{
    self, CREDENTIAL_ENV_KEYS, KEY_SOURCE_ROUTES, ROUTING_ENV_KEYS, check_model_entry, env_key_case_twin, env_key_case_twin_error,
    env_map_of, invalid_env_map_message, is_secret_env_name, non_string_env_keys, non_string_env_value_message,
    settings_env_overrides, shown_env_name, shown_kind, shown_label, validate_env_entry,
};
use crate::links::{self, cleanup_profile, inspect_shared_link, is_primary_dir};
use crate::lock::{DirLockOptions, acquire_dir_lock};
use crate::quota::{QuotaTarget, collect_quotas};
use crate::registry::{
    backup_dir_for, claude_json_path, fold_profile_name, keychain_service, load_registry, name_of, no_registry_error,
    profile_id, registry_problem, require_registry, update_registry, validate_profile_name,
};
use crate::secrets::{delete_secret, resolve_secret, store_secret};
use crate::tools::{self, ADD_PENDING_MARKER, SignInCheck, read_account_info, should_skip_share};
use crate::types::{
    ALL_TOOLS, ApiEndpoint, DiscoveredAccount, DoctorIssue, DoctorResult, Profile, QuotaSnapshot, Registry, SecretSource, Tool,
    UsagePeriod, UsageSummary,
};
use crate::usage::{self, load_usage_store, records_of, seed_seen_sessions, summarize};
use crate::util::{self, data_dir, exists, home, read_json_object, shown, warn, write_json};

fn primary_for(registry: &Registry, tool: Tool) -> PathBuf {
    registry.primary_source(tool).unwrap_or_else(|| tools::default_config_dir(tool))
}

/// Why a profile registered on its tool's primary directory is left alone, and the registry
/// change that settles it.
fn primary_dir_problem(registry: &Registry, id: &str, profile: &Profile) -> String {
    let shown_dir = util::shown_str(&profile.config_dir);
    let registered_primary =
        registry.profiles.iter().find(|(other, p)| other.as_str() != id && p.tool == profile.tool && p.primary()).map(|(k, _)| k);
    let fix = match registered_primary {
        Some(primary) => format!(
            "'{primary}' already registers it as the primary, so remove this duplicate with 'clm remove {id}': that drops only the entry and leaves {shown_dir} as it is."
        ),
        None => format!(
            "To keep it as {}'s primary profile, set \"isPrimary\": true on '{id}' in {}.",
            profile.tool,
            shown(&util::registry_path())
        ),
    };
    format!(
        "'{id}' is registered on {shown_dir}, {}'s primary config directory itself, so clm neither links nor repairs it. {fix}",
        profile.tool
    )
}

// ─── Discovery and init ─────────────────────────────────────────────

/// Accounts signed in under `~/.claude*` and `~/.codex*`.
pub fn discover_accounts() -> Vec<DiscoveredAccount> {
    let h = home();
    let entries = util::read_dir_entries(&h);
    let mut out = Vec::new();
    for tool in ALL_TOOLS {
        let mut dirs: Vec<PathBuf> = entries
            .iter()
            .filter(|(n, t)| t.is_dir() && tools::matches_config_dir_name(tool, n))
            .map(|(n, _)| h.join(n))
            .collect();
        dirs.sort();
        for config_dir in dirs {
            let Some(account) = read_account_info(tool, &config_dir) else { continue };
            let resolved = util::realpath(&config_dir).unwrap_or_else(|| config_dir.clone());
            let default = tools::default_config_dir(tool);
            let is_primary = resolved == util::realpath(&default).unwrap_or(default);
            if tool == Tool::Claude && cfg!(target_os = "macos") {
                let service = keychain_service(&h, &resolved);
                if !tools::has_keychain_credential(&service) && !tools::has_fallback_credential(&config_dir) {
                    continue;
                }
            }
            out.push(DiscoveredAccount { tool, config_dir, email: account.email, org_name: account.org_name, is_primary });
        }
    }
    out
}

fn directory_name(dir: &Path) -> String {
    let base = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    for prefix in [".claude-", ".codex-", ".claude", ".codex"] {
        if let Some(rest) = base.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    base
}

/// The name offered for an account found at `dir`: the directory's name without its prefix,
/// made to fit the name rule.
fn default_profile_name(dir: &Path) -> String {
    let name = directory_name(dir);
    if validate_profile_name(&name).is_ok() {
        return name;
    }
    let mut fitted = String::new();
    let mut in_bad = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            fitted.push(c);
            in_bad = false;
        } else if !in_bad {
            fitted.push('-');
            in_bad = true;
        }
    }
    let fitted = fitted.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()).trim_end_matches('-').to_string();
    if validate_profile_name(&fitted).is_ok() { fitted } else { "profile".into() }
}

/// The names init gives the accounts it found, keyed by config dir: a chosen name, the name an
/// account is already registered under, "default" for the primary, or the directory's name,
/// with `-2`, `-3`, ... where a derived name is taken.
pub fn propose_init_names(accounts: &[DiscoveredAccount], registry: Option<&Registry>, chosen: &HashMap<PathBuf, String>) -> HashMap<PathBuf, String> {
    let mut occupied: HashSet<String> = HashSet::new();
    for tool in ALL_TOOLS {
        let base = data_dir().join("backups").join(tool.name());
        for name in util::read_dir_names(&base) {
            if util::dir_occupied(&base.join(&name)) {
                occupied.insert(fold_profile_name(&profile_id(tool, &name)));
            }
        }
    }
    let empty = Registry::empty();
    let reg = registry.unwrap_or(&empty);
    let registered_name = |a: &DiscoveredAccount| {
        reg.profiles
            .iter()
            .find(|(_, p)| p.tool() == a.tool && util::resolve(&p.dir()) == util::resolve(&a.config_dir))
            .map(|(id, _)| name_of(id).to_string())
    };
    let mut names: HashMap<PathBuf, String> = HashMap::new();
    let mut assigned: HashSet<String> =
        reg.profiles.iter().filter(|(_, p)| p.is_api()).map(|(id, _)| fold_profile_name(id)).collect();
    let mut to_derive = Vec::new();
    for a in accounts {
        match chosen.get(&a.config_dir).cloned().or_else(|| registered_name(a)) {
            Some(name) => {
                assigned.insert(fold_profile_name(&profile_id(a.tool, &name)));
                names.insert(a.config_dir.clone(), name);
            }
            None => to_derive.push(a),
        }
    }
    let registered: HashSet<String> = reg.profiles.keys().map(|k| fold_profile_name(k)).collect();
    let fitted = |a: &DiscoveredAccount| !a.is_primary && default_profile_name(&a.config_dir) != directory_name(&a.config_dir);
    to_derive.sort_by_key(|a| fitted(a));
    for a in to_derive {
        let base = if a.is_primary { "default".to_string() } else { default_profile_name(&a.config_dir) };
        let taken = |name: &str| {
            let folded = fold_profile_name(&profile_id(a.tool, name));
            assigned.contains(&folded) || (!a.is_primary && (registered.contains(&folded) || occupied.contains(&folded)))
        };
        let mut name = base.clone();
        let mut n = 2;
        while taken(&name) {
            name = format!("{base}-{n}");
            n += 1;
        }
        assigned.insert(fold_profile_name(&profile_id(a.tool, &name)));
        names.insert(a.config_dir.clone(), name);
    }
    names
}

fn backup_dir_taken(backup_dir: &Path, id: &str) -> anyhow::Error {
    anyhow!(
        "{} already exists, so '{id}' cannot use it as its backup directory. It may hold another profile's original files: move it somewhere else (or delete it once you are sure nothing in it is needed), then try again.",
        shown(backup_dir)
    )
}

/// Clears the way for a new profile's backup directory: only an empty one goes.
fn clear_backup_dir(backup_dir: &Path, id: &str) -> Result<()> {
    match fs::remove_dir(backup_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTEMPTY) | Some(libc::EEXIST) | Some(libc::ENOTDIR)) => {
            Err(backup_dir_taken(backup_dir, id))
        }
        Err(e) => Err(e.into()),
    }
}

fn claim_backup_dir(backup_dir: &Path, id: &str) -> Result<()> {
    clear_backup_dir(backup_dir, id)?;
    if let Some(parent) = backup_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(backup_dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists { backup_dir_taken(backup_dir, id) } else { e.into() }
    })
}

/// Links a profile dir to the primary and settles what it keeps for itself: the shared steps
/// of init, add and import.
fn link_new_profile(tool: Tool, config_dir: &Path, primary: &Path, backup_dir: &Path, merge: bool, import: bool) -> Result<()> {
    if merge && tool == Tool::Claude && import {
        links::merge_session_state(config_dir, primary);
    }
    let unlinked = links::unshared_links(tool, config_dir, primary, merge);
    links::setup_shared_links(tool, config_dir, primary, merge, backup_dir)?;
    links::settle_unshared(tool, config_dir, primary, backup_dir, merge, &unlinked, false)?;
    if tool == Tool::Claude {
        if import {
            links::merge_plugin_files(&config_dir.join("plugins"), &primary.join("plugins"));
        }
        links::setup_plugins_dir(config_dir, primary, backup_dir)?;
    }
    Ok(())
}

pub struct InitOptions {
    pub names: HashMap<PathBuf, String>,
    /// A bare claude profile name the user picked as active.
    pub default_profile: Option<String>,
    pub merge_sessions: bool,
    pub force: bool,
}

/// Registers the accounts found, linking each non-primary one to its tool's primary. API
/// profiles, which discovery cannot find, are carried over as they are.
pub fn initialize_registry(accounts: &[DiscoveredAccount], options: InitOptions) -> Result<Registry> {
    if let Some(problem) = registry_problem() {
        bail!(problem);
    }
    let existing = load_registry()?;
    let carried: Vec<(String, Profile)> =
        existing.iter().flat_map(|r| r.profiles.iter()).filter(|(_, p)| p.is_api()).map(|(k, p)| (k.clone(), p.clone())).collect();
    let carried_dirs: HashSet<PathBuf> = carried.iter().map(|(_, p)| util::resolve(&p.dir())).collect();
    let accounts: Vec<&DiscoveredAccount> =
        accounts.iter().filter(|a| !carried_dirs.contains(&util::resolve(&a.config_dir))).collect();
    let owned: Vec<DiscoveredAccount> = accounts.iter().map(|a| (*a).clone()).collect();
    let names = propose_init_names(&owned, existing.as_ref(), &options.names);

    struct Planned<'a> {
        account: &'a DiscoveredAccount,
        id: String,
        backup_dir: Option<PathBuf>,
        kept: bool,
    }
    let mut planned: Vec<Planned> = Vec::new();
    let mut init_ids: HashMap<String, (String, bool, bool)> =
        carried.iter().map(|(id, _)| (fold_profile_name(id), (id.clone(), false, true))).collect();
    for account in &accounts {
        let name = names.get(&account.config_dir).cloned().unwrap_or_default();
        let id = profile_id(account.tool, &name);
        let kept = existing.as_ref().and_then(|r| r.profiles.get(&id)).is_some_and(|p| {
            p.tool() == account.tool && util::resolve(&p.dir()) == util::resolve(&account.config_dir)
        });
        if !kept {
            validate_profile_name(&name)?;
        }
        if let Some((clash, clash_kept, api)) = init_ids.get(&fold_profile_name(&id)) {
            if *api {
                bail!("'{clash}' is an API profile, which init keeps. Give '{id}' another name.");
            }
            if *clash == id {
                bail!("Two accounts are both named '{id}'. Give each account its own name.");
            }
            if !(*clash_kept && kept) {
                bail!("'{clash}' and '{id}' name the same profile (names are compared without case). Give each account its own name.");
            }
        }
        init_ids.insert(fold_profile_name(&id), (id.clone(), kept, false));
        let tool_primary = tools::default_config_dir(account.tool);
        if !account.is_primary && is_primary_dir(&account.config_dir, &tool_primary) {
            bail!(
                "Cannot set up {} as '{id}': it is {}'s primary config directory, which every profile shares. Register it as the primary profile instead.",
                shown(&account.config_dir),
                account.tool
            );
        }
        let backup_dir = if account.is_primary { None } else { Some(backup_dir_for(account.tool, &name)?) };
        if let Some(dir) = &backup_dir {
            if !kept && util::dir_occupied(dir) {
                return Err(backup_dir_taken(dir, &id));
            }
            let (_, moving) = links::codex_state_to_move(account.tool, &account.config_dir, &tool_primary, dir, options.merge_sessions, false);
            links::refuse_while_codex_runs(&account.config_dir, &moving, "clm init --auto --force", options.force)?;
        }
        planned.push(Planned { account, id, backup_dir, kept });
    }

    fs::create_dir_all(data_dir())?;
    let mut registry = Registry::empty();
    for tool in accounts.iter().map(|a| a.tool).chain(carried.iter().map(|(_, p)| p.tool())) {
        registry
            .primary_sources
            .entry(tool.name().to_string())
            .or_insert_with(|| tools::default_config_dir(tool).to_string_lossy().into_owned());
    }
    for plan in &planned {
        let a = plan.account;
        let mut profile = Profile::new(a.tool, &a.config_dir.to_string_lossy(), &a.email);
        profile.org_name = a.org_name.clone();
        profile.is_primary = Some(a.is_primary);
        profile.merge_sessions = if a.is_primary { None } else { Some(options.merge_sessions) };
        registry.profiles.insert(plan.id.clone(), profile);
        if let Some(dir) = &plan.backup_dir {
            if !plan.kept {
                claim_backup_dir(dir, &plan.id)?;
            } else {
                fs::create_dir_all(dir)?;
            }
            let primary = primary_for(&registry, a.tool);
            link_new_profile(a.tool, &a.config_dir, &primary, dir, options.merge_sessions, true)?;
        }
    }

    let saved = update_registry(|current| {
        if let Some(current) = &current {
            for (id, profile) in &current.profiles {
                if !profile.is_api() || registry.profiles.contains_key(id) {
                    continue;
                }
                registry.profiles.insert(id.clone(), profile.clone());
                registry
                    .primary_sources
                    .entry(profile.tool.clone())
                    .or_insert_with(|| tools::default_config_dir(profile.tool()).to_string_lossy().into_owned());
            }
        }
        let picked = options.default_profile.as_ref().map(|n| profile_id(Tool::Claude, n));
        for tool in ALL_TOOLS {
            let active = current.as_ref().and_then(|c| c.active(tool).cloned());
            let next = picked
                .clone()
                .filter(|p| tool == Tool::Claude && registry.profiles.contains_key(p))
                .or_else(|| active.filter(|a| registry.profiles.get(a).is_some_and(|p| p.tool() == tool)))
                .or_else(|| planned.iter().find(|p| p.account.tool == tool).map(|p| p.id.clone()));
            if let Some(next) = next {
                registry.active_profiles.insert(tool.name().to_string(), next);
            }
        }
        Ok(Some(registry.clone()))
    })?
    .expect("init writes the registry");
    for plan in &planned {
        let _ = fs::remove_file(plan.account.config_dir.join(ADD_PENDING_MARKER));
    }
    // Usage history is kept across a re-init, and across an import from clausona: seeding
    // below only marks what is new as seen.
    for (id, profile) in &saved.profiles {
        if profile.tool() == Tool::Claude {
            seed_seen_sessions(id, &profile.dir());
        }
    }
    Ok(saved)
}

// ─── Adding ─────────────────────────────────────────────────────────

fn profile_id_clash(registry: &Registry, id: &str) -> Option<String> {
    let folded = fold_profile_name(id);
    registry.profiles.keys().find(|k| fold_profile_name(k) == folded).cloned()
}

fn assert_profile_id_available(registry: &Registry, id: &str, signing_in: bool) -> Result<()> {
    let relogin = |existing: &str| {
        if signing_in && registry.profiles.get(existing).is_some_and(|p| !p.is_api()) {
            format!(" Run `clm login {existing}` to sign in again.")
        } else {
            String::new()
        }
    };
    if registry.profiles.contains_key(id) {
        bail!("Profile '{id}' already exists.{}", relogin(id));
    }
    if let Some(clash) = profile_id_clash(registry, id) {
        bail!("Profile '{clash}' already exists (names are compared without case).{}", relogin(&clash));
    }
    Ok(())
}

/// `add --from` refuses the primary, a registered dir, the home dir, and a dir that holds one.
fn assert_importable(registry: &Registry, tool: Tool, config_dir: &Path, primary: &Path) -> Result<()> {
    let target = util::real_or_resolved(config_dir);
    let shown_dir = shown(config_dir);
    if target == util::real_or_resolved(primary) {
        bail!("Cannot add {shown_dir}: it is {tool}'s primary config directory, which every profile shares.");
    }
    for (id, profile) in &registry.profiles {
        if target == util::real_or_resolved(&profile.dir()) {
            bail!("Cannot add {shown_dir}: it is already registered as '{id}'.");
        }
    }
    if target == util::real_or_resolved(&home()) {
        bail!("Cannot add {shown_dir}: it is the home directory, not a config directory.");
    }
    for managed in std::iter::once(primary.to_path_buf()).chain(registry.profiles.values().map(|p| p.dir())) {
        if util::is_within(&target, &util::real_or_resolved(&managed)) {
            bail!("Cannot add {shown_dir}: it holds {}, which clm already manages.", shown(&managed));
        }
    }
    Ok(())
}

fn remove_dir_command(dir: &Path) -> String {
    let quote = |v: &str| {
        if v.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)) { v.to_string() } else { util::posix_quote(v) }
    };
    let h = home();
    match dir.strip_prefix(&h) {
        Ok(rest) if !rest.as_os_str().is_empty() => format!("rm -rf ~/{}", quote(&rest.to_string_lossy())),
        _ => format!("rm -rf {}", quote(&dir.to_string_lossy())),
    }
}

const ADD_LOCK: DirLockOptions = DirLockOptions { stale_ms: 30_000, update_ms: 10_000, wait_ms: 0, retry_ms: 100 };

fn with_add_lock<T>(tool: Tool, name: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let path = util::locks_dir().join(format!("add-{tool}-{}.lock", fold_profile_name(name)));
    fs::create_dir_all(util::locks_dir())?;
    let lock = acquire_dir_lock(&path, &ADD_LOCK)?;
    if lock.is_none() {
        bail!(
            "Another `clm add` of '{}' (or of the same name in another case) is in progress. Wait for it to finish; if it was interrupted, try again in 30 seconds.",
            profile_id(tool, name)
        );
    }
    let result = f();
    drop(lock);
    result
}

/// Records a finished profile, checking the id again against the registry as it is now.
fn register_profile(id: &str, profile: Profile, primary: &Path) -> Result<Registry> {
    let saved = update_registry(|current| {
        let mut current = current.ok_or_else(no_registry_error)?;
        assert_profile_id_available(&current, id, false).map_err(|e| {
            anyhow!("{e} Another clm process registered it while this add was in progress; run `clm list` to see it.")
        })?;
        let tool = profile.tool.clone();
        current.profiles.insert(id.to_string(), profile.clone());
        current.primary_sources.entry(tool).or_insert_with(|| primary.to_string_lossy().into_owned());
        Ok(Some(current))
    })?;
    Ok(saved.expect("register writes the registry"))
}

pub fn configdir_warnings(tool: Tool, config_dir: &Path) -> Vec<String> {
    let limit = if cfg!(target_os = "linux") { 107 } else { 103 };
    let resolved = util::real_or_resolved(config_dir);
    tools::unix_sockets(tool)
        .iter()
        .filter_map(|(socket, purpose)| {
            let socket_path = format!("{}/{socket}", resolved.display());
            let bytes = socket_path.len();
            (bytes > limit).then(|| {
                format!(
                    "{} is too long a path for {}: {purpose} binds a socket at {socket_path}, which is {bytes} bytes where this system allows {limit}, so it fails without saying so - keep the directory's real path to {} bytes or fewer",
                    config_dir.display(),
                    tool.product(),
                    limit - socket.len() - 1
                )
            })
        })
        .collect()
}

pub struct Added {
    pub email: String,
    pub credential_unconfirmed: Option<String>,
    pub warnings: Vec<String>,
}

fn carry_onboarding(primary: &Path, config_dir: &Path) -> Result<()> {
    let primary_json = read_json_object(&claude_json_path(&home(), primary));
    let json_path = config_dir.join(".claude.json");
    let mut profile_json = read_json_object(&json_path);
    let mut changed = !json_path.exists();
    for key in ["hasCompletedOnboarding", "lastOnboardingVersion"] {
        if let Some(v) = primary_json.get(key)
            && !profile_json.contains_key(key) {
                profile_json.insert(key.into(), v.clone());
                changed = true;
            }
    }
    if changed {
        write_json(&json_path, &Value::Object(profile_json), None)?;
    }
    Ok(())
}

/// Adds a subscription profile: imports an existing dir with `from`, or creates
/// `~/.<tool>-<name>` and runs the tool's own sign-in into it.
pub fn add_profile(tool: Tool, name: &str, from: Option<&str>, merge: bool) -> Result<Added> {
    validate_profile_name(name)?;
    let registry = require_registry()?;
    let id = profile_id(tool, name);
    assert_profile_id_available(&registry, &id, from.is_none())?;
    with_add_lock(tool, name, || {
        let registry = require_registry()?;
        assert_profile_id_available(&registry, &id, from.is_none())?;
        let primary = primary_for(&registry, tool);
        let h = home();

        if let Some(from) = from {
            let config_dir = util::expand_tilde(from);
            assert_importable(&registry, tool, &config_dir, &primary)?;
            let account = read_account_info(tool, &config_dir).ok_or_else(|| anyhow!("Could not read account info from config dir."))?;
            let backup_dir = backup_dir_for(tool, name)?;
            claim_backup_dir(&backup_dir, &id)?;
            if let Err(e) = link_new_profile(tool, &config_dir, &primary, &backup_dir, merge, true) {
                let _ = cleanup_profile(tool, name, &id, &config_dir, &primary, false, false);
                bail!("Failed to set up profile '{name}': {e}");
            }
            let mut profile = Profile::new(tool, &config_dir.to_string_lossy(), &account.email);
            profile.org_name = account.org_name.clone();
            profile.merge_sessions = Some(merge);
            if let Err(e) = register_profile(&id, profile, &primary) {
                let _ = cleanup_profile(tool, name, &id, &config_dir, &primary, false, false);
                return Err(e);
            }
            let _ = fs::remove_file(config_dir.join(ADD_PENDING_MARKER));
            if tool == Tool::Claude {
                seed_seen_sessions(&id, &config_dir);
            }
            return Ok(Added { email: account.email, credential_unconfirmed: None, warnings: configdir_warnings(tool, &config_dir) });
        }

        let config_dir = h.join(format!(".{tool}-{name}"));
        let reusing = if exists(&config_dir) {
            assert_importable(&registry, tool, &config_dir, &primary)?;
            if !exists(&config_dir.join(ADD_PENDING_MARKER)) {
                let shown_dir = shown(&config_dir);
                if read_account_info(tool, &config_dir).is_some() {
                    bail!("{shown_dir} already exists. Use --from {shown_dir} to import it instead.");
                }
                bail!(
                    "{shown_dir} already exists but has no signed-in account to import. If it is a leftover from an interrupted add and holds nothing you need, remove it with `{}` and run the add again; otherwise choose another profile name.",
                    remove_dir_command(&config_dir)
                );
            }
            true
        } else {
            false
        };
        let backup_dir = backup_dir_for(tool, name)?;
        clear_backup_dir(&backup_dir, &id)?;
        if !reusing {
            fs::create_dir_all(&config_dir)?;
            if let Err(e) = fs::write(
                config_dir.join(ADD_PENDING_MARKER),
                "Created by `clm add`, which has not finished setting up this directory.\nRunning the same add again reuses it.\n",
            ) {
                util::remove_all(&config_dir);
                return Err(e.into());
            }
        }

        let mut credential_unconfirmed = None;
        if !tools::already_signed_in(tool, &config_dir) {
            if !tools::run_login(tool, &config_dir) {
                util::remove_all(&config_dir);
                bail!("{tool} login failed.");
            }
            match tools::verify_sign_in(tool, &config_dir) {
                SignInCheck::Ok => {}
                SignInCheck::SignedOut(detail) => {
                    util::remove_all(&config_dir);
                    return Err(no_credential_error(tool, &id, &detail, &format!("clm add {id}")));
                }
                SignInCheck::Unknown(detail) => credential_unconfirmed = Some(detail),
            }
        }
        if tool == Tool::Claude {
            carry_onboarding(&primary, &config_dir)?;
        }
        let Some(account) = read_account_info(tool, &config_dir) else {
            util::remove_all(&config_dir);
            bail!("Login succeeded but account metadata is missing.");
        };
        if let Err(e) = claim_backup_dir(&backup_dir, &id) {
            util::remove_all(&config_dir);
            return Err(e);
        }
        if let Err(e) = link_new_profile(tool, &config_dir, &primary, &backup_dir, merge, false) {
            let _ = cleanup_profile(tool, name, &id, &config_dir, &primary, false, false);
            util::remove_all(&config_dir);
            bail!("Failed to set up profile '{name}': {e}");
        }
        let mut profile = Profile::new(tool, &config_dir.to_string_lossy(), &account.email);
        profile.org_name = account.org_name.clone();
        profile.merge_sessions = Some(merge);
        if let Err(e) = register_profile(&id, profile, &primary) {
            let _ = cleanup_profile(tool, name, &id, &config_dir, &primary, false, false);
            util::remove_all(&config_dir);
            return Err(e);
        }
        let _ = fs::remove_file(config_dir.join(ADD_PENDING_MARKER));
        if tool == Tool::Claude {
            seed_seen_sessions(&id, &config_dir);
        }
        Ok(Added { email: account.email, credential_unconfirmed, warnings: configdir_warnings(tool, &config_dir) })
    })
}

fn no_credential_error(tool: Tool, id: &str, detail: &str, retry: &str) -> anyhow::Error {
    let next = if cfg!(target_os = "macos") {
        format!("Check that the login Keychain is unlocked, then run '{retry}' again.")
    } else {
        format!("Run '{retry}' again.")
    };
    anyhow!("The sign-in finished, but {} stored no credential for {id} ({detail}). {next}", tool.product())
}

/// Checks a key source before anything is stored: the reference to persist, and the value to
/// store for the keychain source.
pub fn check_secret_source(secret: &SecretSource, value: Option<&str>) -> Result<Option<String>> {
    match secret {
        SecretSource::Keychain => match value.map(str::trim) {
            Some(v) if !v.is_empty() => Ok(Some(v.to_string())),
            _ => bail!("no API key supplied for the keychain source"),
        },
        SecretSource::Env(name) => {
            if carries_credential_token(name) {
                bail!(
                    "Pass the name of the variable that holds the key - export GW_KEY=… in the shell that runs claude, then --key-from env:GW_KEY. What followed env: looks like an API key rather than a name, so it was not stored. If it is a variable's name, copy the variable to a plainer name the same way and pass that."
                );
            }
            if !util::is_posix_env_name(name) {
                bail!(
                    "Invalid key variable name: use letters, digits and underscores, starting with a letter or underscore. Pass the variable's name, not the key."
                );
            }
            Ok(None)
        }
        SecretSource::Command(run) => {
            if run.trim().is_empty() {
                bail!("The key command is empty.");
            }
            Ok(None)
        }
    }
}

/// The base URL rule, worded for the CLI. No message repeats the URL.
pub fn parse_base_url(base_url: &str) -> Result<url::Url> {
    match check_base_url(base_url) {
        Ok(url) => Ok(url),
        Err(BaseUrlProblem::Empty | BaseUrlProblem::Unparseable) => bail!("Invalid base URL: must be an absolute http:// or https:// URL."),
        Err(BaseUrlProblem::Scheme(scheme)) => {
            if has_bare_userinfo(base_url) {
                bail!("Invalid base URL: it must not carry credentials. Supply the key through the key source instead.");
            }
            match scheme {
                None => bail!("Invalid base URL: it has no http:// or https:// scheme."),
                Some(s) => bail!("Invalid base URL: the scheme must be http or https, not '{s}'."),
            }
        }
        Err(BaseUrlProblem::Credentials) => {
            bail!("Invalid base URL: it must not carry credentials. Supply the key through the key source instead.")
        }
        Err(BaseUrlProblem::KeyShaped) => bail!(
            "Invalid base URL: give the endpoint without the key, and the key through {KEY_SOURCE_ROUTES}. Part of this URL looks like an API key, so it was not stored. If none of it is one, write the URL into api.baseUrl in ~/.clm/profiles.json by hand (for a new profile, after adding it with any other URL)."
        ),
        Err(BaseUrlProblem::KeyParameter(p)) => bail!(
            "Invalid base URL: give the endpoint without its '{p}' parameter, and the key through {KEY_SOURCE_ROUTES}. A query parameter by that name carries a credential, so the URL was not stored."
        ),
    }
}

pub fn check_label(label: &str, at_add: bool) -> Result<String> {
    let trimmed = label.trim();
    if carries_credential_token(trimmed) {
        bail!(
            "Choose a label that reads as a name, such as --label \"OpenRouter GLM\", and pass the key through {KEY_SOURCE_ROUTES}. This label looks like an API key, so it was not stored."
        );
    }
    if trimmed.is_empty() {
        let hint = if at_add { " Leave --label out to use the endpoint's host." } else { "" };
        bail!("Label cannot be blank: it is the name `clm list` shows for this profile.{hint}");
    }
    Ok(trimmed.to_string())
}

pub fn check_auth_scheme(scheme: &str) -> Result<String> {
    if scheme != "bearer" && scheme != "api-key" {
        bail!("Invalid auth scheme: must be 'bearer' or 'api-key'.");
    }
    Ok(scheme.to_string())
}

pub fn default_auth_scheme(hostname: &str) -> &'static str {
    if checks::is_anthropic_host(hostname) { "api-key" } else { "bearer" }
}

/// The new API profile's config dir, once the name is free.
pub fn free_api_config_dir(registry: &Registry, tool: Tool, name: &str) -> Result<PathBuf> {
    assert_profile_id_available(registry, &profile_id(tool, name), false)?;
    let dir = home().join(format!(".claude-{name}"));
    if exists(&dir) {
        bail!("{} already exists. Choose another profile name.", shown(&dir));
    }
    Ok(dir)
}

/// The other API profiles that read the same env or command key source for another endpoint.
pub fn key_sharers_elsewhere(id: &str, secret: Option<&SecretSource>, base_url: &str, registry: &Registry) -> Vec<String> {
    let origin = origin_of(base_url);
    registry
        .profiles
        .iter()
        .filter(|(other, p)| {
            other.as_str() != id
                && p.is_api()
                && shares_secret_source(p.api.as_ref().and_then(|a| a.secret()).as_ref(), secret)
                && (origin.is_none() || origin_of(p.api.as_ref().map(|a| a.base_url.as_str()).unwrap_or("")) != origin)
        })
        .map(|(k, _)| k.clone())
        .collect()
}

pub struct ApiAdd {
    pub name: String,
    pub base_url: String,
    pub auth_scheme: String,
    pub secret: SecretSource,
    pub secret_value: Option<String>,
    pub label: Option<String>,
    pub env: Map<String, Value>,
    pub merge: bool,
}

/// Adds an API profile. Every input is checked before the first side effect.
pub fn add_api_profile(tool: Tool, opts: ApiAdd) -> Result<(PathBuf, Vec<String>)> {
    validate_profile_name(&opts.name)?;
    if tool != Tool::Claude {
        bail!("API profiles are Claude Code only in this version.");
    }
    let base_url = opts.base_url.trim().to_string();
    let url = parse_base_url(&base_url)?;
    check_auth_scheme(&opts.auth_scheme)?;
    let label = match &opts.label {
        None => url_host(&url),
        Some(l) => check_label(l, true)?,
    };
    let to_store = check_secret_source(&opts.secret, opts.secret_value.as_deref())?;
    let keys: Vec<String> = opts.env.keys().cloned().collect();
    for (key, value) in &opts.env {
        let value = value.as_str().unwrap_or("");
        check_model_entry(key, value, true)?;
        validate_env_entry(key, value, true).map_err(|e| anyhow!(e))?;
        if let Some(twin) = env_key_case_twin(key, keys.iter(), true) {
            bail!(env_key_case_twin_error(key, &twin));
        }
    }
    let registry = require_registry()?;
    let id = profile_id(tool, &opts.name);
    free_api_config_dir(&registry, tool, &opts.name)?;

    with_add_lock(tool, &opts.name, || {
        let current = require_registry()?;
        let config_dir = free_api_config_dir(&current, tool, &opts.name)?;
        let primary = primary_for(&current, tool);
        let backup_dir = backup_dir_for(tool, &opts.name)?;
        claim_backup_dir(&backup_dir, &id)?;
        let result: Result<Registry> = (|| {
            fs::create_dir_all(&config_dir)?;
            carry_onboarding(&primary, &config_dir)?;
            links::setup_shared_links(tool, &config_dir, &primary, opts.merge, &backup_dir)?;
            links::setup_plugins_dir(&config_dir, &primary, &backup_dir)?;
            if let Some(v) = &to_store {
                store_secret(&id, v)?;
            }
            let mut profile = Profile::new(tool, &config_dir.to_string_lossy(), "");
            profile.kind = Some(json!("api"));
            profile.label = Some(label.clone());
            profile.merge_sessions = Some(opts.merge);
            profile.api = Some(ApiEndpoint {
                base_url: base_url.clone(),
                auth_scheme: opts.auth_scheme.clone(),
                secret: opts.secret.to_value(),
                extra: Map::new(),
            });
            profile.env = Some(Value::Object(opts.env.clone()));
            register_profile(&id, profile, &primary)
        })();
        match result {
            Ok(saved) => {
                seed_seen_sessions(&id, &config_dir);
                let sharers = key_sharers_elsewhere(&id, Some(&opts.secret), &base_url, &saved);
                Ok((config_dir, sharers))
            }
            Err(e) => {
                let _ = cleanup_profile(tool, &opts.name, &id, &config_dir, &primary, true, false);
                util::remove_all(&config_dir);
                bail!("Failed to set up profile '{}': {e}", opts.name)
            }
        }
    })
}

// ─── Changing a profile ─────────────────────────────────────────────

/// Relinks a profile: picks up entries the primary gained, takes out links it should not
/// have, and puts back what it keeps for itself.
pub fn repair_profile(id: &str, force: bool) -> Result<usize> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    if profile.primary() {
        return Ok(0);
    }
    let tool = profile.tool();
    let primary = primary_for(&registry, tool);
    if is_primary_dir(&profile.dir(), &primary) {
        bail!(primary_dir_problem(&registry, id, profile));
    }
    let backup_dir = backup_dir_for(tool, name_of(id))?;
    let merge = profile.merges();
    let config_dir = profile.dir();
    if merge && tool == Tool::Claude {
        links::merge_session_state(&config_dir, &primary);
    }
    let (unlinked, moving) = links::codex_state_to_move(tool, &config_dir, &primary, &backup_dir, merge, true);
    links::refuse_while_codex_runs(&config_dir, &moving, &format!("clm repair {id} --force"), force)?;
    let repaired = links::setup_shared_links(tool, &config_dir, &primary, merge, &backup_dir)?;
    if tool == Tool::Claude {
        links::setup_plugins_dir(&config_dir, &primary, &backup_dir)?;
    }
    if tools::names_shared_entries(tool) {
        links::settle_unshared(tool, &config_dir, &primary, &backup_dir, merge, &unlinked, true)?;
    } else {
        links::restore_skipped_from_backup(tool, &config_dir, &primary, &backup_dir, merge)?;
    }
    Ok(repaired)
}

/// Turns session sharing with the primary on or off. False when it already was.
pub fn update_session_mode(id: &str, merge: bool, force: bool) -> Result<bool> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    if profile.primary() {
        bail!("Cannot change session mode for the primary profile.");
    }
    let tool = profile.tool();
    let primary = primary_for(&registry, tool);
    if is_primary_dir(&profile.dir(), &primary) {
        bail!(primary_dir_problem(&registry, id, profile));
    }
    if profile.merges() == merge {
        return Ok(false);
    }
    let backup_dir = backup_dir_for(tool, name_of(id))?;
    let config_dir = profile.dir();
    let (unlinked, moving) = links::codex_state_to_move(tool, &config_dir, &primary, &backup_dir, merge, true);
    let flag = if merge { "--merge-sessions" } else { "--separate-sessions" };
    links::refuse_while_codex_runs(&config_dir, &moving, &format!("clm config {id} {flag} --force"), force)?;
    if merge && tool == Tool::Claude {
        links::merge_session_state(&config_dir, &primary);
    }
    update_registry(|current| {
        let mut current = current.ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        current.profiles.get_mut(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?.merge_sessions = Some(merge);
        Ok(Some(current))
    })?;
    links::setup_shared_links(tool, &config_dir, &primary, merge, &backup_dir)?;
    if tool == Tool::Claude {
        links::setup_plugins_dir(&config_dir, &primary, &backup_dir)?;
    }
    if tools::names_shared_entries(tool) {
        links::settle_unshared(tool, &config_dir, &primary, &backup_dir, merge, &unlinked, true)?;
    } else if !merge {
        links::restore_skipped_from_backup(tool, &config_dir, &primary, &backup_dir, false)?;
    }
    Ok(true)
}

/// Sets and unsets env-map entries; `replace` saves `set` as the whole map (`--edit`).
pub fn update_profile_env(id: &str, set: &Map<String, Value>, unset: &[String], replace: bool) -> Result<()> {
    update_registry(|registry| {
        let mut registry = registry.ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let profile = registry.profiles.get_mut(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let current = env_map_of(profile.env.as_ref());
        if current.is_none() && !replace {
            let message = invalid_env_map_message(id);
            let mut chars = message.chars();
            let first = chars.next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default();
            bail!("{first}{}.", chars.as_str());
        }
        let mut env = if replace { Map::new() } else { current.unwrap_or_default() };
        for (key, value) in set {
            let v = value.as_str().unwrap_or("");
            check_model_entry(key, v, false)?;
            validate_env_entry(key, v, profile.is_api()).map_err(|e| anyhow!(e))?;
            env.insert(key.clone(), value.clone());
        }
        for key in unset {
            env.shift_remove(key);
        }
        let keys: Vec<String> = env.keys().cloned().collect();
        for key in set.keys() {
            if !env.contains_key(key) {
                continue;
            }
            if let Some(twin) = env_key_case_twin(key, keys.iter(), profile.is_api()) {
                bail!(env_key_case_twin_error(key, &twin));
            }
        }
        profile.env = Some(Value::Object(env));
        Ok(Some(registry))
    })?;
    Ok(())
}

pub fn missing_endpoint_remedy(id: &str) -> String {
    format!(
        "run 'clm remove {id}' and then 'clm add <new-name> --api --base-url <url>' - remove keeps the config directory, so the old name stays taken"
    )
}

pub fn require_endpoint<'a>(id: &str, profile: &'a Profile) -> Result<&'a ApiEndpoint> {
    if !profile.is_api() {
        bail!("Profile '{id}' is not an API profile.");
    }
    profile.api.as_ref().ok_or_else(|| {
        anyhow!(
            "Profile '{id}' has no endpoint in ~/.clm/profiles.json, so there is nothing for config to change - {}.",
            missing_endpoint_remedy(id)
        )
    })
}

/// Changes where an API profile's key comes from. True when a key clm had stored was
/// deleted.
pub fn update_profile_secret(id: &str, secret: &SecretSource, value: Option<&str>) -> Result<bool> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    require_endpoint(id, profile)?;
    let to_store = check_secret_source(secret, value)?;
    if let Some(v) = &to_store {
        store_secret(id, v)?;
    }
    update_registry(|current| {
        let mut current = current.ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let profile = current.profiles.get_mut(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        require_endpoint(id, profile)?;
        profile.api.as_mut().unwrap().secret = secret.to_value();
        Ok(Some(current))
    })?;
    if to_store.is_some() {
        return Ok(false);
    }
    Ok(delete_secret(id).unwrap_or(false))
}

pub struct ApiUpdate {
    pub profile: Profile,
    pub previous_host: Option<String>,
    pub host: Option<String>,
    pub followed_label: bool,
    pub followed_auth: bool,
    pub host_default_auth: Option<&'static str>,
    pub cleartext: bool,
    pub shared_with: Vec<String>,
}

/// Changes an API profile's endpoint, auth scheme or label. `add`'s own defaults follow a new
/// host while they are still the old host's.
pub fn update_profile_api(id: &str, base_url: Option<&str>, auth: Option<&str>, label: Option<&str>) -> Result<ApiUpdate> {
    let mut out: Option<ApiUpdate> = None;
    update_registry(|registry| {
        let mut registry = registry.ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let profile = registry.profiles.get(id).cloned().ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
        let api = require_endpoint(id, &profile)?.clone();
        let new_url = base_url.map(|b| b.trim().to_string()).unwrap_or_else(|| api.base_url.clone());
        let url = match base_url {
            Some(_) => Some(parse_base_url(&new_url)?),
            None => None,
        };
        let chosen_auth = auth.map(check_auth_scheme).transpose()?;
        let chosen_label = label.map(|l| check_label(l, false)).transpose()?;
        let previous = check_base_url(&api.base_url).ok();
        let follow_label = chosen_label.is_none()
            && url.is_some()
            && previous.as_ref().is_some_and(|p| profile.label.as_deref() == Some(url_host(p).as_str()));
        let follow_auth = chosen_auth.is_none()
            && url.is_some()
            && previous.as_ref().is_some_and(|p| api.auth_scheme == default_auth_scheme(&url_hostname(p)))
            && url.as_ref().is_some_and(|u| default_auth_scheme(&url_hostname(u)) != api.auth_scheme);
        let new_label = if follow_label { url.as_ref().map(url_host) } else { chosen_label.or(profile.label.clone()) };
        let new_auth = chosen_auth.unwrap_or_else(|| {
            if follow_auth { default_auth_scheme(&url_hostname(url.as_ref().unwrap())).to_string() } else { api.auth_scheme.clone() }
        });
        let host_default = url.as_ref().map(|u| default_auth_scheme(&url_hostname(u)));
        let mut updated = profile.clone();
        updated.label = new_label;
        let mut new_api = api.clone();
        new_api.base_url = new_url.clone();
        new_api.auth_scheme = new_auth.clone();
        updated.api = Some(new_api);
        registry.profiles.insert(id.to_string(), updated.clone());
        let previous_host = previous.as_ref().map(url_host);
        let host = url.as_ref().map(url_host).or(previous_host.clone());
        out = Some(ApiUpdate {
            profile: updated,
            previous_host: previous_host.clone(),
            host: host.clone(),
            followed_label: follow_label,
            followed_auth: follow_auth,
            host_default_auth: if chosen_auth_is_none(auth) && host_default.is_some_and(|d| d != new_auth) && host != previous_host {
                host_default
            } else {
                None
            },
            cleartext: url.as_ref().is_some_and(|u| {
                sends_key_in_clear(u) && !(previous.as_ref().is_some_and(|p| p.scheme() == "http" && url_host(p) == url_host(u)))
            }),
            shared_with: key_sharers_elsewhere(id, api.secret().as_ref(), &new_url, &registry),
        });
        Ok(Some(registry))
    })?;
    Ok(out.expect("the update ran"))
}

fn chosen_auth_is_none(auth: Option<&str>) -> bool {
    auth.is_none()
}

// ─── Login, remove, run ─────────────────────────────────────────────

pub enum LoginStatus {
    Ok,
    OtherAccount(String),
    Unverified,
}

/// Re-runs a profile's sign-in. Which account signs in is the browser's choice, so another
/// account than the one registered is reported, not refused.
pub fn login_profile(id: &str) -> Result<(Profile, LoginStatus, Option<String>)> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).cloned().ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    if profile.is_api() {
        bail!("'{id}' is an API profile. Change its key with 'clm config {id} --key'.");
    }
    let tool = profile.tool();
    if !tools::run_login(tool, &profile.dir()) {
        bail!("{tool} login failed.");
    }
    let caveat = match tools::verify_sign_in(tool, &profile.dir()) {
        SignInCheck::Ok => None,
        SignInCheck::SignedOut(detail) => return Err(no_credential_error(tool, id, &detail, &format!("clm login {id}"))),
        SignInCheck::Unknown(detail) => Some(detail),
    };
    let status = match read_account_info(tool, &profile.dir()) {
        None => LoginStatus::Unverified,
        Some(a) => {
            let registered = &profile.email;
            let is_email = registered.contains('@');
            let other = is_email == a.email.contains('@')
                && if is_email { a.email.to_lowercase() != registered.to_lowercase() } else { &a.email != registered };
            if other { LoginStatus::OtherAccount(a.email) } else { LoginStatus::Ok }
        }
    };
    Ok((profile, status, caveat))
}

/// Removes a profile: its links come out, what was set aside goes back, a stored key is
/// deleted. Its config dir and history stay.
pub fn remove_profile(id: &str) -> Result<()> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).cloned().ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    let registry_shown = shown(&util::registry_path());
    let unremovable = |reason: &str| anyhow!("Profile '{id}' {reason}, so it cannot be removed. Remove its entry from {registry_shown} by hand.");
    if profile.primary() {
        bail!("Cannot remove the primary profile.");
    }
    let Some(tool) = Tool::parse(&profile.tool) else {
        return Err(unremovable("has no known tool (claude or codex)"));
    };
    if !id.starts_with(&format!("{tool}:")) {
        return Err(unremovable(&format!("is not listed as '{tool}:<name>'")));
    }
    if !Path::new(&profile.config_dir).is_absolute() {
        return Err(unremovable("has no config directory path"));
    }
    let primary = primary_for(&registry, tool);
    let name = name_of(id);
    let backup_dir = backup_dir_for(tool, name)?;
    let own_backup = data_dir().join("backups");
    let folded_own = fold_profile_name(&backup_dir.to_string_lossy());
    let sharer = registry
        .profiles
        .iter()
        .find(|(other, p)| {
            if other.as_str() == id || p.primary() {
                return false;
            }
            let theirs = fold_profile_name(&util::resolve(&own_backup.join(&p.tool).join(name_of(other))).to_string_lossy());
            Path::new(&theirs).starts_with(&folded_own) || Path::new(&folded_own).starts_with(&theirs)
        })
        .map(|(k, _)| k.clone());
    let on_primary_dir = is_primary_dir(&profile.dir(), &primary);
    let shown_dir = util::shown_str(&profile.config_dir);
    let notice = if on_primary_dir {
        Some(format!(
            "{id}: {shown_dir} is {tool}'s primary config directory itself, so only its entry was removed. {shown_dir} was left as it is{}.",
            if util::dir_occupied(&backup_dir) {
                format!(", and so was {}, which holds what clm set aside from it", shown(&backup_dir))
            } else {
                String::new()
            }
        ))
    } else {
        sharer.as_ref().map(|s| {
            format!(
                "{id}: left {} in place because '{s}' keeps its backup there too. Nothing from it was restored into {shown_dir}; copy back anything you need from it by hand.",
                shown(&backup_dir)
            )
        })
    };
    let owns_key = profile.is_api() || profile.api.as_ref().and_then(|a| a.secret()) == Some(SecretSource::Keychain);
    cleanup_profile(tool, name, id, &profile.dir(), &primary, owns_key, sharer.is_some() || on_primary_dir)?;
    if let Some(n) = notice {
        warn(&n);
    }
    update_registry(|current| {
        let Some(mut current) = current else { return Ok(None) };
        if !current.profiles.contains_key(id) {
            return Ok(None);
        }
        current.profiles.shift_remove(id);
        let remaining: Vec<String> = current
            .profiles
            .iter()
            .filter(|(k, p)| k.starts_with(&format!("{tool}:")) && p.tool == tool.name() && Path::new(&p.config_dir).is_absolute())
            .map(|(k, _)| k.clone())
            .collect();
        if current.active(tool).map(|a| a == id).unwrap_or(false) {
            match remaining.first() {
                Some(next) => {
                    current.active_profiles.insert(tool.name().into(), next.clone());
                }
                None => {
                    current.active_profiles.remove(tool.name());
                }
            }
        }
        if remaining.is_empty() {
            current.primary_sources.remove(tool.name());
        }
        Ok(Some(current))
    })?;
    Ok(())
}

/// The environment `clm run` starts a profile's tool with.
pub fn resolve_profile_env(id: &str) -> Result<(Tool, Vec<(String, String)>, Vec<String>)> {
    let registry = require_registry()?;
    let profile = registry.profiles.get(id).ok_or_else(|| anyhow!("Profile '{id}' not found."))?;
    let tool = profile.tool();
    let built = env::build_profile_env(id, profile);
    for w in &built.warnings {
        warn(w);
    }
    let mut unset: Vec<String> = built.unset.clone();
    if !built.env.contains_key(tools::config_env_var(tool)) {
        unset.push(tools::config_env_var(tool).into());
    }
    if tool == Tool::Claude {
        let primary = primary_for(&registry, Tool::Claude);
        links::sync_plugins_json(&profile.dir(), &primary);
    }
    Ok((tool, built.env.into_iter().collect(), unset))
}

// ─── Listing ────────────────────────────────────────────────────────

pub struct ListItem {
    pub id: String,
    pub profile: Profile,
    pub is_active: bool,
    pub model: Option<String>,
    pub quota: Option<QuotaSnapshot>,
    pub today: UsageSummary,
    pub week: UsageSummary,
    pub month: UsageSummary,
    pub total: UsageSummary,
}

impl ListItem {
    /// The entry `list --json` prints: never the key, its source, or the env map.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), json!(self.id));
        m.insert("tool".into(), json!(self.profile.tool));
        if let Some(k) = shown_kind(self.profile.kind.as_ref()) {
            m.insert("kind".into(), json!(k));
        }
        m.insert("email".into(), json!(self.profile.email));
        if let Some(l) = shown_label(self.profile.label.as_deref()) {
            m.insert("label".into(), json!(l));
        }
        if let Some(o) = &self.profile.org_name {
            m.insert("orgName".into(), json!(o));
        }
        m.insert("configDir".into(), json!(self.profile.config_dir));
        m.insert("isPrimary".into(), json!(self.profile.primary()));
        m.insert("isActive".into(), json!(self.is_active));
        if let Some(ms) = self.profile.merge_sessions {
            m.insert("mergeSessions".into(), json!(ms));
        }
        if let Some(model) = &self.model {
            m.insert("model".into(), json!(model));
        }
        if let Some(q) = &self.quota {
            m.insert("quota".into(), serde_json::to_value(q).unwrap_or(Value::Null));
        }
        for (k, s) in [("today", self.today), ("week", self.week), ("month", self.month), ("total", self.total)] {
            m.insert(k.into(), serde_json::to_value(s).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }
}

pub fn list_profiles(quota: bool, refresh: bool, renew: bool) -> Result<Vec<ListItem>> {
    let Some(registry) = load_registry()? else { return Ok(Vec::new()) };
    let store = load_usage_store();
    let mut quotas: HashMap<String, QuotaSnapshot> = HashMap::new();
    if quota {
        let targets = registry
            .profiles
            .iter()
            .filter(|(_, p)| !p.is_api())
            .map(|(id, p)| QuotaTarget { id: id.clone(), tool: p.tool(), config_dir: p.dir() })
            .collect();
        quotas = collect_quotas(targets, refresh, renew);
    }
    Ok(registry
        .profiles
        .iter()
        .map(|(id, p)| {
            let records = records_of(&store, id);
            ListItem {
                id: id.clone(),
                profile: p.clone(),
                is_active: registry.active(p.tool()).map(|a| a == id).unwrap_or(false),
                model: env::profile_model(p),
                quota: quotas.remove(id),
                today: summarize(&records, UsagePeriod::Today),
                week: summarize(&records, UsagePeriod::Week),
                month: summarize(&records, UsagePeriod::Month),
                total: summarize(&records, UsagePeriod::All),
            }
        })
        .collect())
}

/// One profile's usage, or every profile's.
pub fn usage_summary(id: Option<&str>, period: UsagePeriod) -> Result<Option<Vec<(String, UsageSummary)>>> {
    let Some(registry) = load_registry()? else { return Ok(None) };
    let store = usage::load_usage_store();
    let ids: Vec<String> = match id {
        Some(id) => vec![id.to_string()],
        None => registry.profiles.keys().cloned().collect(),
    };
    Ok(Some(ids.into_iter().map(|id| { let s = summarize(&records_of(&store, &id), period); (id, s) }).collect()))
}

// ─── Doctor ─────────────────────────────────────────────────────────

fn base_url_problem(base_url: &str, remedy: &str) -> Option<String> {
    let problem = check_base_url(base_url).err()?;
    Some(match problem {
        BaseUrlProblem::Empty => format!("no base URL configured for this API profile - {remedy}"),
        BaseUrlProblem::Unparseable => format!("the base URL is not an absolute http:// or https:// URL - {remedy}"),
        BaseUrlProblem::Scheme(_) if has_bare_userinfo(base_url) => {
            format!("the base URL carries a username or password - put the key in the key source instead, and {remedy}")
        }
        BaseUrlProblem::Scheme(None) => format!("the base URL has no http:// or https:// scheme - {remedy}"),
        BaseUrlProblem::Scheme(Some(s)) => format!("the base URL's scheme is '{s}', not http or https - {remedy}"),
        BaseUrlProblem::Credentials => {
            format!("the base URL carries a username or password - put the key in the key source instead, and {remedy}")
        }
        BaseUrlProblem::KeyShaped => format!(
            "give the base URL without the key and keep the key in the key source - {remedy} - since part of it looks like an API key; if none of it is one, the profile works as it is"
        ),
        BaseUrlProblem::KeyParameter(p) => format!(
            "give the base URL without its '{p}' parameter and keep the key in the key source - {remedy} - since a query parameter by that name carries a credential"
        ),
    })
}

/// The commands that move a plain-text credential out of an env map: (commands, keyFrom,
/// keepInShell, noEndpoint).
pub fn plaintext_env_remedy(id: &str, profile: &Profile, key: &str, anthropic_credential: bool) -> (Vec<String>, Option<String>, bool, bool) {
    let unset = format!("clm config {id} --unset {key}");
    if !anthropic_credential {
        return (vec![unset], None, true, false);
    }
    if !profile.is_api() {
        return (vec![unset], None, false, false);
    }
    let Some(api) = &profile.api else {
        return (vec![format!("clm remove {id}"), "clm add <new-name> --api --base-url <url>".into()], None, false, true);
    };
    match api.secret() {
        None | Some(SecretSource::Keychain) => (vec![format!("clm config {id} --key"), unset], None, false, false),
        s => (vec![unset], Some(key_source_phrase(s.as_ref())), false, false),
    }
}

fn evaluate_api_health(id: &str, profile: &Profile, registry: &Registry, config_dir_exists: bool, primary: Option<&Path>) -> Vec<DoctorIssue> {
    let mut issues = Vec::new();
    if !config_dir_exists {
        issues.push(DoctorIssue::error(
            "missing_config_dir",
            format!(
                "config directory {} is missing - create the directory again, then run 'clm repair {id}'. Failing that, remove and re-add the profile, which deletes a stored key: 'clm remove {id}', then 'clm add {id} --api --base-url <url>'",
                profile.config_dir
            ),
        ));
    }
    let base_url = profile.api.as_ref().map(|a| a.base_url.clone()).unwrap_or_default();
    let remedy =
        if profile.api.is_some() { format!("run 'clm config {id} --base-url <url>'") } else { missing_endpoint_remedy(id) };
    let url_problem = base_url_problem(&base_url, &remedy);
    if let Some(p) = &url_problem {
        issues.push(DoctorIssue::error("invalid_api_config", p.clone()));
    }
    if profile.env.as_ref().and_then(|e| e.as_object()).is_some_and(|m| m.contains_key("ANTHROPIC_BASE_URL")) {
        issues.push(DoctorIssue::warning(
            "env_overrides_endpoint",
            format!(
                "ANTHROPIC_BASE_URL in this profile's env map overrides the endpoint shown for it, so the key goes wherever that says - run 'clm config {id} --unset ANTHROPIC_BASE_URL', then 'clm config {id} --base-url <url>' to change the endpoint"
            ),
        ));
    }
    if let Some(api) = &profile.api {
        if api.auth_scheme != "bearer" && api.auth_scheme != "api-key" {
            issues.push(DoctorIssue::error(
                "invalid_api_config",
                format!(
                    "the auth scheme in ~/.clm/profiles.json is not bearer or api-key, so the key goes out as ANTHROPIC_API_KEY - run 'clm config {id} --auth bearer' or 'clm config {id} --auth api-key'"
                ),
            ));
        }
        match api.secret() {
            None => issues.push(DoctorIssue::error(
                "invalid_api_config",
                format!(
                    "the key source in ~/.clm/profiles.json is not keychain, env or command, so where the key comes from is unknown - run 'clm config {id} --key' to store one, or 'clm config {id} --key-from env:<NAME>' to read one"
                ),
            )),
            Some(secret) => {
                if let Err(e) = resolve_secret(id, Some(&secret)) {
                    let msg = e.to_string();
                    issues.push(DoctorIssue::error(
                        "missing_api_secret",
                        format!("API key unavailable: {}", if msg.trim().is_empty() { "unknown" } else { msg.trim() }),
                    ));
                }
            }
        }
    }
    let endpoint = if url_problem.is_some() { "this profile's endpoint".to_string() } else { redact_base_url(&base_url) };
    let sharers = profile.api.as_ref().map(|a| key_sharers_elsewhere(id, a.secret().as_ref(), &a.base_url, registry)).unwrap_or_default();
    if url_problem.is_none() && !sharers.is_empty() {
        issues.push(DoctorIssue::warning(
            "shared_key_source",
            format!(
                "this profile's key comes from {}, which {} {} too for a different endpoint, so one key goes to {} - if this endpoint takes a key of its own, run 'clm config {id} --key-from env:<ANOTHER_NAME>' (or --key, to store it)",
                key_source_phrase(profile.api.as_ref().and_then(|a| a.secret()).as_ref()),
                sharers.join(", "),
                if sharers.len() == 1 { "uses" } else { "use" },
                if sharers.len() == 1 { "both" } else { "all of them" }
            ),
        ));
    }
    let settings_path = profile.dir().join("settings.json");
    let settings_shown = shown(&settings_path);
    let settings: Option<Map<String, Value>> = match fs::read_to_string(&settings_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Map::new()),
        Err(_) => None,
        Ok(raw) => match serde_json::from_str(&raw) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        },
    };
    match settings {
        None => issues.push(DoctorIssue::warning(
            "unreadable_settings",
            format!("{settings_shown} could not be read, so apiKeyHelper and its env block were not checked - fix or remove it"),
        )),
        Some(settings) => {
            let shared = primary.is_some_and(|p| inspect_shared_link(&settings_path, &p.join("settings.json")).points_to_source);
            let where_ = if shared { format!("{settings_shown} (shared with the primary)") } else { settings_shown.clone() };
            let mut names: Vec<&str> = vec!["ANTHROPIC_BASE_URL"];
            names.extend_from_slice(CREDENTIAL_ENV_KEYS);
            names.extend_from_slice(ROUTING_ENV_KEYS);
            names.push("ANTHROPIC_MODEL");
            for key in settings_env_overrides(settings.get("env"), &names) {
                let shown_key = shown_env_name(&key);
                let message = format!(
                    "{shown_key} is set in the env block of {where_}, and Claude Code applies it over this profile - move it out of that settings.json into the profile that needs it: 'clm config <that profile> --set {shown_key}=VALUE'"
                );
                issues.push(if key.eq_ignore_ascii_case("ANTHROPIC_MODEL") {
                    DoctorIssue::warning("settings_env_override", message)
                } else {
                    DoctorIssue::error("settings_env_override", message)
                });
            }
            if settings.get("apiKeyHelper").and_then(|h| h.as_str()).is_some_and(|h| !h.trim().is_empty()) {
                issues.push(DoctorIssue::warning(
                    "shared_api_key_helper",
                    format!(
                        "apiKeyHelper in {where_} {} for this profile, so the key it prints can reach {endpoint}",
                        if shared { "also runs" } else { "runs" }
                    ),
                ));
            }
        }
    }
    let mut keys: Vec<String> = profile.env.as_ref().and_then(|e| e.as_object()).map(|m| m.keys().cloned().collect()).unwrap_or_default();
    keys.sort();
    for key in keys {
        if carries_credential_token(&key) {
            issues.push(DoctorIssue::warning(
                "plaintext_env_secret",
                format!(
                    "a setting whose name is shaped like an API key is stored in plain text in ~/.clm/profiles.json, and launch ignores it - remove it with 'clm config {id} --edit'"
                ),
            ));
            continue;
        }
        if !is_secret_env_name(&key) {
            continue;
        }
        let (commands, key_from, keep_in_shell, no_endpoint) = plaintext_env_remedy(id, profile, &key, CREDENTIAL_ENV_KEYS.contains(&key.as_str()));
        let remedy = commands.iter().map(|c| format!("'{c}'")).collect::<Vec<_>>().join(" and then ");
        let advice = if keep_in_shell {
            format!(
                "if it holds a secret, your shell's environment can hold it instead, but the hook then passes it to every {} profile launched from that shell, not just this one; if that is fine, run {remedy}, and if not, leave it here, where output hides it",
                profile.tool
            )
        } else if no_endpoint {
            format!("this profile has no endpoint to keep a key for, so if it holds one, run {remedy} - remove keeps the config directory, so the old name stays taken")
        } else if let Some(from) = key_from {
            format!("this profile's key already comes from {from}, so if it holds that key, run {remedy}")
        } else {
            format!("if it holds this profile's API key, run {remedy}")
        };
        issues.push(DoctorIssue::warning("plaintext_env_secret", format!("{key} is stored in plain text in ~/.clm/profiles.json - {advice}")));
    }
    issues
}

/// The root value of `key` in a TOML document, before the first table.
fn toml_root_value(text: &str, key: &str) -> Option<String> {
    for line in text.trim_start_matches('\u{feff}').lines() {
        let statement = line.split('#').next().unwrap_or("").trim();
        if statement.is_empty() {
            continue;
        }
        if statement.starts_with('[') {
            return None;
        }
        if let Some((k, v)) = statement.split_once('=') {
            let k = k.trim().trim_matches(|c| c == '"' || c == '\'');
            if k == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn sqlite_home_issues(profile: &Profile, primary: Option<&Path>) -> Vec<DoctorIssue> {
    let config_path = profile.dir().join("config.toml");
    let config = util::read_text(&config_path).unwrap_or_default();
    if toml_root_value(&config, "sqlite_home").is_some() {
        let shared = !profile.primary() && primary.is_some_and(|p| inspect_shared_link(&config_path, &p.join("config.toml")).points_to_source);
        return vec![DoctorIssue::warning(
            "shared_sqlite_home",
            format!(
                "sqlite_home is set in {}{}, so Codex keeps this profile's SQLite state - threads, memories, logs - in the directory it names, along with every other profile that reads it - remove it to keep each account's state in its own CODEX_HOME",
                config_path.display(),
                if shared { " (shared with the primary)" } else { "" }
            ),
        )];
    }
    let own = env_map_of(profile.env.as_ref()).is_some_and(|m| m.contains_key("CODEX_SQLITE_HOME"));
    if std::env::var("CODEX_SQLITE_HOME").is_ok_and(|v| !v.trim().is_empty()) && !own {
        return vec![DoctorIssue::warning(
            "shared_sqlite_home",
            "CODEX_SQLITE_HOME is set in this environment, so every Codex profile started from it keeps its SQLite state - threads, memories, logs - in that one directory rather than in its own CODEX_HOME - unset it to keep each account's state apart".into(),
        )];
    }
    Vec::new()
}

pub fn doctor_profiles() -> Result<Vec<DoctorResult>> {
    let Some(registry) = load_registry()? else { return Ok(Vec::new()) };
    let h = home();
    let codex_count = registry.profiles.values().filter(|p| p.tool() == Tool::Codex).count();
    let mut results = Vec::new();
    for (id, profile) in &registry.profiles {
        let mut issues: Vec<DoctorIssue> = Vec::new();
        match env_map_of(profile.env.as_ref()) {
            None => issues.push(DoctorIssue::error("invalid_env_map", invalid_env_map_message(id))),
            Some(map) => {
                for key in non_string_env_keys(&map) {
                    issues.push(DoctorIssue::error("invalid_env_map", non_string_env_value_message(id, &key)));
                }
            }
        }
        if shown_kind(profile.kind.as_ref()).as_deref() == Some("unknown") {
            issues.push(DoctorIssue::error(
                "invalid_profile_kind",
                format!(
                    "the profile's kind in ~/.clm/profiles.json is not subscription or api, so clm treats it as a subscription profile - remove it with 'clm remove {id}' and add it again under a new name, since remove keeps the config directory and the old name stays taken"
                ),
            ));
        }
        let tool = profile.tool();
        let primary = registry.primary_source(tool);
        let dir = profile.dir();
        let config_dir_missing = profile.is_api() && !exists(&dir);

        if profile.is_api() {
            issues.extend(evaluate_api_health(id, profile, &registry, !config_dir_missing, primary.as_deref()));
        } else {
            if read_account_info(tool, &dir).is_none() {
                issues.push(DoctorIssue::error(
                    "missing_json",
                    if tool == Tool::Claude {
                        ".claude.json is missing or missing oauthAccount.emailAddress".into()
                    } else {
                        "auth.json is missing or id_token is unparseable".into()
                    },
                ));
            }
            if tool == Tool::Claude {
                if cfg!(target_os = "macos") {
                    let resolved = util::realpath(&dir).unwrap_or_else(|| dir.clone());
                    let service = keychain_service(&h, &resolved);
                    if !tools::has_keychain_credential(&service) && !tools::has_fallback_credential(&dir) {
                        issues.push(DoctorIssue::error(
                            "missing_keychain",
                            format!(
                                "{service} (account {}) not found in Keychain, and .credentials.json is missing or has no access token",
                                tools::claude_keychain_account()
                            ),
                        ));
                    }
                } else if tools::read_credential(tool, &dir).is_none() {
                    issues.push(DoctorIssue::error(
                        "missing_oauth",
                        ".credentials.json is missing or has no access token - sign in from this profile".into(),
                    ));
                }
            }
        }

        let primary_or_default = primary.clone().unwrap_or_else(|| tools::default_config_dir(tool));
        let on_primary_dir = !profile.primary() && is_primary_dir(&dir, &primary_or_default);
        if on_primary_dir {
            issues.push(DoctorIssue::error("primary_config_dir", primary_dir_problem(&registry, id, profile)));
        }

        if let (Some(primary), false, false) = (&primary, config_dir_missing, on_primary_dir) {
            let merge = profile.merges();
            let primary_entries = util::read_dir_entries(primary);
            let primary_names: HashSet<String> = primary_entries.iter().map(|(n, _)| n.clone()).collect();
            for (name, ft) in util::read_dir_entries(&dir) {
                let target = dir.join(&name);
                let source = primary.join(&name);
                let info = inspect_shared_link(&target, &source);
                if should_skip_share(tool, &name, merge) {
                    if !profile.primary() && info.points_to_source && links::holds_nothing_of_its_own(&target) {
                        issues.push(if tools::names_shared_entries(tool) {
                            let (wrong, why) = tools::unshared_risk(&name);
                            DoctorIssue::error(
                                if wrong { "wrong_account_link" } else { "shared_account_state" },
                                format!("{name} links to the primary's, {why}"),
                            )
                        } else {
                            DoctorIssue::error("stale_symlink", format!("{name} is symlinked to primary but should not be shared"))
                        });
                    }
                    continue;
                }
                if profile.primary() {
                    continue;
                }
                if info.is_shared_link && info.points_to_source && !info.target_exists && util::is_symlink(&source) {
                    let shown_source = shown(&source);
                    issues.push(DoctorIssue::error(
                        "primary_broken_link",
                        format!(
                            "{name} links to the primary's {shown_source}, which is itself a broken link. clm does not change the primary: fix {shown_source} there, or remove it."
                        ),
                    ));
                    continue;
                }
                if info.is_shared_link && !info.target_exists {
                    issues.push(DoctorIssue::error("broken_symlink", format!("{name} shared link points to a missing target")));
                }
                if !info.points_to_source && primary_names.contains(&name) {
                    issues.push(DoctorIssue::error("local_override", format!("{name} replaced an expected shared link")));
                }
                if ft.is_file() && tools::rewrites_whole(tool, &name) && primary_names.contains(&name) && info.points_to_source && links::holds_nothing_of_its_own(&target) {
                    issues.push(DoctorIssue::warning(
                        "needs_symlink",
                        format!("{name} is shared by a hard link, which its next save will split, since the file is saved by renaming a new one over it - repair makes it a symbolic link"),
                    ));
                }
            }
            if !profile.primary() {
                for (name, ft) in &primary_entries {
                    if ft.is_dir() && !should_skip_share(tool, name, merge) && !exists(&dir.join(name)) {
                        issues.push(DoctorIssue::error(
                            "missing_shared_link",
                            format!("{name}/ is shared in primary but missing here — run 'clm repair'"),
                        ));
                    }
                }
            }
        }

        if !profile.primary() && !on_primary_dir && tool == Tool::Claude && !config_dir_missing {
            let plugins = dir.join("plugins");
            if util::is_real_dir(&plugins) {
                let known = read_json_object(&plugins.join("known_marketplaces.json"));
                let on_disk: Vec<String> = util::read_dir_entries(&plugins.join("marketplaces"))
                    .into_iter()
                    .filter(|(_, t)| t.is_dir())
                    .map(|(n, _)| n)
                    .collect();
                let mut out_of_sync = on_disk.iter().any(|n| !known.contains_key(n));
                if !out_of_sync {
                    for (name, entry) in &known {
                        if !links::is_managed_marketplace(entry, &dir) {
                            continue;
                        }
                        let expected = dir.join("plugins").join("marketplaces").join(name).to_string_lossy().into_owned();
                        if !on_disk.contains(name) || entry.get("installLocation").and_then(|v| v.as_str()) != Some(expected.as_str()) {
                            out_of_sync = true;
                            break;
                        }
                    }
                }
                if out_of_sync {
                    issues.push(DoctorIssue::error(
                        "plugins_out_of_sync",
                        "plugins/ marketplaces and known_marketplaces.json are out of sync".into(),
                    ));
                }
            }
        }
        if !config_dir_missing {
            for message in configdir_warnings(tool, &dir) {
                issues.push(DoctorIssue::warning("socket_path_too_long", message));
            }
        }
        if tool == Tool::Codex && codex_count > 1 {
            issues.extend(sqlite_home_issues(profile, primary.as_deref()));
        }
        let healthy = issues.iter().all(|i| i.is_warning());
        results.push(DoctorResult {
            name: id.clone(),
            kind: shown_kind(profile.kind.as_ref()),
            email: profile.email.clone(),
            label: shown_label(profile.label.as_deref()),
            config_dir: profile.config_dir.clone(),
            is_primary: profile.primary(),
            healthy,
            issues,
        });
    }
    Ok(results)
}

// ─── Uninstall ──────────────────────────────────────────────────────

pub fn uninstall() -> Vec<String> {
    let mut removed = Vec::new();
    let h = home();
    if let Ok(Some(registry)) = load_registry() {
        for (id, profile) in &registry.profiles {
            if profile.primary() {
                continue;
            }
            let tool = profile.tool();
            let primary = primary_for(&registry, tool);
            let shown_dir = util::shown_str(&profile.config_dir);
            let on_primary = is_primary_dir(&profile.dir(), &primary);
            let owns_key = profile.is_api() || profile.api.as_ref().and_then(|a| a.secret()) == Some(SecretSource::Keychain);
            match cleanup_profile(tool, name_of(id), id, &profile.dir(), &primary, owns_key, false) {
                Ok(()) => removed.push(if on_primary {
                    format!("profile: {id} ({shown_dir} is {tool}'s primary config directory itself, so it was left as it is)")
                } else {
                    format!("profile: {id} (symlinks stripped, data preserved at {shown_dir})")
                }),
                Err(e) => warn(&format!("uninstall: could not clean up profile {id}: {e}")),
            }
        }
    }
    for rc in [h.join(".zshrc"), h.join(".bashrc"), h.join(".bash_profile")] {
        if let Some(content) = util::read_text(&rc) {
            // The hook line, and the comment install.sh writes above it.
            let filtered: Vec<&str> = content
                .split('\n')
                .filter(|l| !l.contains("clm shell-init") && !l.starts_with("# clm: switch Claude Code"))
                .collect();
            let filtered = filtered.join("\n");
            if filtered != content && fs::write(&rc, filtered).is_ok() {
                removed.push(format!("shell-init: {}", rc.display()));
            }
        }
    }
    let dir = data_dir();
    if exists(&dir) {
        let backups = dir.join("backups");
        util::remove_empty_dirs(&backups);
        if util::dir_occupied(&backups) {
            for entry in util::read_dir_names(&dir) {
                if entry != "backups" {
                    util::remove_all(&dir.join(entry));
                }
            }
            removed.push(format!("data: {} (all but its backups)", dir.display()));
            removed.push(format!(
                "backups kept: {} holds what clm set aside and could not put back. Move it somewhere else, or delete it once nothing in it is needed.",
                shown(&backups)
            ));
        } else {
            util::remove_all(&dir);
            removed.push(format!("data: {}", dir.display()));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        match fs::remove_file(&exe) {
            Ok(()) => removed.push(format!("binary: {}", exe.display())),
            Err(_) => removed.push(format!("binary: {} (manual removal required)", exe.display())),
        }
    }
    removed
}
