//! Argument parsing and what each command prints. One rule runs through every message: an
//! option's value is never echoed back, since one keystroke away from it is the key.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::checks::{CREDENTIAL_AS_NAME_ERROR, describe_secret_source, key_source_phrase, looks_like_credential, sends_key_in_clear, url_host, url_hostname};
use crate::env::{
    self, CLAUDE_ENV_CATALOG, controlled_env_keys, env_map_of, hidden_env_keys, is_credential_env_key, is_secret_env_name,
    non_string_env_keys, printable, redact_profile, shown_env_name,
};
use crate::format;
use crate::links;
use crate::registry::{self, load_registry, no_registry_error, parse_profile_ref, profile_id, registry_problem, require_registry};
use crate::secrets::{prompt_secret, secret_store_name};
use crate::service::{self, ApiAdd, InitOptions, LoginStatus};
use crate::shell::{LAUNCH_MARKER, render_posix_exports, render_shell_init};
use crate::style::*;
use crate::tools;
use crate::types::{ALL_TOOLS, Profile, SecretSource, Tool, UsagePeriod};
use crate::usage;
use crate::util::{self, home};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const ADD_VALUE_FLAGS: &[&str] = &["--from", "--base-url", "--model", "--auth", "--key-from", "--label", "--set"];
const CONFIG_VALUE_FLAGS: &[&str] = &["--set", "--unset", "--model", "--key-from", "--base-url", "--auth", "--label"];
const API_ONLY_FLAGS: &[&str] = &["--base-url", "--model", "--auth", "--key-from", "--label", "--set"];

fn known_flags(command: &str) -> Option<(Vec<&'static str>, Vec<&'static str>)> {
    let flags: Vec<&'static str> = match command {
        "init" => vec!["--auto", "--merge-sessions", "--force"],
        "add" => [&["--merge-sessions", "--api"][..], ADD_VALUE_FLAGS].concat(),
        "use" | "login" | "remove" | "shell-init" | "uninstall" | "version" => vec![],
        "list" => vec!["--json", "--no-quota", "--no-renew", "--refresh"],
        "usage" => vec!["--json"],
        "current" | "doctor" | "_launch" | "_shell-env" => vec!["--json"],
        "config" => [&["--merge-sessions", "--separate-sessions", "--force", "--key", "--edit", "--show", "--json"][..], CONFIG_VALUE_FLAGS].concat(),
        "repair" => vec!["--force"],
        _ => return None,
    };
    let prefixes: Vec<&'static str> = match command {
        "add" => ADD_VALUE_FLAGS.to_vec(),
        "config" => CONFIG_VALUE_FLAGS.to_vec(),
        "usage" => vec!["--period"],
        _ => vec![],
    };
    Some((flags, prefixes))
}

fn validate_flags(command: &str, args: &[String]) -> Result<()> {
    let Some((flags, prefixes)) = known_flags(command) else { return Ok(()) };
    for arg in args {
        if !arg.starts_with('-') || arg == "--help" || arg == "-h" || flags.contains(&arg.as_str()) {
            continue;
        }
        if prefixes.iter().any(|p| arg.starts_with(&format!("{p}="))) {
            continue;
        }
        bail!("Unknown option: {}\nRun `clm {command} --help` for usage.", arg.split('=').next().unwrap_or(arg));
    }
    Ok(())
}

/// `--flag value` and `--flag=value`, every occurrence in order.
fn option_values(args: &[String], flag: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == flag {
            match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => {
                    out.push(v.clone());
                    i += 1;
                }
                _ => bail!("{flag} needs a value."),
            }
        } else if let Some(v) = arg.strip_prefix(&format!("{flag}=")) {
            out.push(v.to_string());
        }
        i += 1;
    }
    Ok(out)
}

fn option_value(args: &[String], flag: &str) -> Result<Option<String>> {
    let values = option_values(args, flag)?;
    if values.len() > 1 {
        bail!("{flag} was given more than once. Pass it at most once.");
    }
    Ok(values.into_iter().next())
}

/// The bare arguments, skipping whatever follows a value-carrying option.
fn positional(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut consumed = vec![false; args.len()];
    for (i, a) in args.iter().enumerate() {
        if value_flags.contains(&a.as_str()) && i + 1 < args.len() {
            consumed[i + 1] = true;
        }
    }
    args.iter().enumerate().filter(|(i, a)| !a.starts_with("--") && !consumed[*i]).map(|(_, a)| a.clone()).collect()
}

fn parse_assignment(input: &str, flag: &str) -> Result<(String, String)> {
    match input.find('=') {
        Some(i) if i > 0 => Ok((input[..i].to_string(), input[i + 1..].to_string())),
        _ => bail!("Expected {flag} KEY=VALUE, for example {flag} ANTHROPIC_MODEL=my-model."),
    }
}

fn parse_secret_source(input: &str) -> Result<SecretSource> {
    if input == "keychain" {
        return Ok(SecretSource::Keychain);
    }
    if let Some(name) = input.strip_prefix("env:") {
        if name.is_empty() {
            bail!("Usage: --key-from env:VARIABLE_NAME");
        }
        return Ok(SecretSource::Env(name.into()));
    }
    if let Some(run) = input.strip_prefix("command:") {
        if run.is_empty() {
            bail!("Usage: --key-from command:\"<shell command>\"");
        }
        return Ok(SecretSource::Command(run.into()));
    }
    bail!("Invalid --key-from: use keychain, env:NAME, or command:\"<shell command>\".")
}

fn parse_auth(input: &str) -> Result<String> {
    if input != "bearer" && input != "api-key" {
        bail!("Invalid --auth: use bearer or api-key.");
    }
    Ok(input.into())
}

fn parse_model(input: &str, at_add: bool) -> Result<String> {
    let model = input.trim().to_string();
    env::check_model_entry("ANTHROPIC_MODEL", &model, at_add)?;
    Ok(model)
}

const MODEL_TWICE: &str = "ANTHROPIC_MODEL is what --model sets. Pass one or the other.";
const NO_KEY_SUPPLIED: &str = "No API key supplied. Type it at the prompt, pipe it in (printf %s \"$KEY\" | clm …), or read it from elsewhere with --key-from env:NAME.";
const ADD_API_USAGE: &str = "Usage: clm add <profile> --api --base-url <url> [--model <id>] [--auth bearer|api-key] [--key-from <source>] [--label <name>] [--set KEY=VALUE]";
const CONFIG_USAGE: &str = "Usage: clm config <profile> [--model <id>] [--set KEY=VALUE] [--unset KEY] [--base-url <url>] [--auth bearer|api-key] [--label <name>] [--key | --key-from <source>] [--edit] [--show] [--merge-sessions | --separate-sessions]";

fn warn_line(msg: &str) {
    eprintln!("  {} {msg}", warn_icon());
}

/// The env map is plain text in profiles.json: a warning, with the commands that undo it,
/// for each name that says it holds a secret.
fn warn_plaintext_env(id: &str, profile: &Profile, keys: &[String]) {
    for key in keys {
        if !is_secret_env_name(key) {
            continue;
        }
        let credential = is_credential_env_key(key);
        let (commands, key_from, _, no_endpoint) = service::plaintext_env_remedy(id, profile, key, credential);
        let listed: String = commands.iter().map(|c| format!("      {}\n", accent(c))).collect();
        let advice = if !credential {
            format!(
                "    If it carries a secret, your shell's environment can hold it instead - but the hook then passes it to every {} profile launched from that shell, not just this one. If that is fine, remove this copy:\n{listed}    If only this profile should have it, leave it here: output hides it.\n",
                profile.tool
            )
        } else if no_endpoint {
            format!("    This profile has no endpoint to keep a key for, so if it carries one, add the profile again - under a new name, since remove keeps the config directory:\n{listed}")
        } else if profile.is_api() {
            match key_from {
                None => format!("    If it carries this profile's API key, move the key to the credential store and remove this copy:\n{listed}"),
                Some(from) => format!("    This profile's key already comes from {from}, so if it carries that key, remove this copy:\n{listed}"),
            }
        } else if profile.tool() == Tool::Codex {
            format!("    Codex does not read this variable, so here it only sits in plain text. Remove it:\n{listed}")
        } else {
            format!(
                "    A subscription profile signs in with its account, so if it carries an API key it does not belong here:\n{listed}    To use an API key instead, give it an API profile of its own:\n      {}\n",
                accent("clm add --help")
            )
        };
        eprint!("  {} {key} is stored in plain text in ~/.clm/profiles.json.\n{advice}", warn_icon());
    }
}

fn warn_unset_key_variable(secret: &SecretSource) {
    if let SecretSource::Env(name) = secret
        && std::env::var(name).map(|v| v.is_empty()).unwrap_or(true) {
            eprintln!(
                "  {} The key now comes from {}, which is not set in this shell.\n    Export it where claude runs - in your shell's rc file, for one - or the next launch has no key.",
                warn_icon(),
                describe_secret_source(Some(secret))
            );
        }
}

fn cleartext_note(host: &str) {
    warn_line(&format!("{host} is plain http, so the key crosses the network unencrypted."));
}

fn unconfirmed_warning(tool: Tool, id: &str, detail: &str) -> String {
    format!(
        "  {} Signed in, but could not confirm that {} stored a credential for {id} ({detail})\n       {}",
        warn_icon(),
        tool.product(),
        dim(&format!("If {tool} asks you to sign in, run {}", accent(&format!("clm login {id}"))))
    )
}

fn ask(question: &str) -> Option<String> {
    print!("{question}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

fn shown_config_path(dir: &str) -> String {
    util::shown_str(dir)
}

// ─── config --show ──────────────────────────────────────────────────

fn show_profile(id: &str, profile: &Profile, as_json: bool) -> String {
    let shown = redact_profile(profile);
    let hidden = hidden_env_keys(profile.env.as_ref());
    if as_json {
        let mut p = Map::new();
        p.insert("id".into(), json!(id));
        p.insert("kind".into(), shown.get("kind").cloned().unwrap_or(json!("subscription")));
        if let Some(l) = shown.get("label") {
            p.insert("label".into(), l.clone());
        }
        p.insert("email".into(), json!(profile.email));
        p.insert("configDir".into(), json!(profile.config_dir));
        p.insert("isPrimary".into(), json!(profile.primary()));
        p.insert("mergeSessions".into(), json!(profile.merges()));
        if let Some(a) = shown.get("api") {
            p.insert("api".into(), a.clone());
        }
        p.insert("env".into(), shown.get("env").cloned().unwrap_or(json!({})));
        p.insert("hiddenEnvKeys".into(), json!(hidden));
        return serde_json::to_string_pretty(&json!({ "profile": p, "catalog": CLAUDE_ENV_CATALOG })).unwrap_or_default();
    }
    let kind = shown.get("kind").and_then(|v| v.as_str()).unwrap_or("subscription").to_string();
    let mut lines = vec![
        row("Kind", &kind),
        row("Account", &env::profile_display_name(profile)),
        row("Config", &dim(&profile.config_dir)),
    ];
    if let Some(api) = shown.get("api") {
        lines.push(row("Endpoint", api.get("baseUrl").and_then(|v| v.as_str()).unwrap_or("")));
        lines.push(row("Auth", api.get("authScheme").and_then(|v| v.as_str()).unwrap_or("")));
        lines.push(row("Key", &describe_secret_source(profile.api.as_ref().and_then(|a| a.secret()).as_ref())));
    }
    if !profile.primary() {
        lines.push(row("Sessions", if profile.merges() { "merged" } else { "separated" }));
    }
    let footer = dim("Run `clm config <profile> --show --json` for the full advanced-settings catalog.");
    match shown.get("env") {
        Some(Value::String(_)) => {
            lines.push(row("Settings", &format!("<hidden> {}", dim("(not a map of NAME: value - see clm doctor)"))));
        }
        env_value => {
            let map = env_value.and_then(|v| v.as_object()).cloned().unwrap_or_default();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            lines.push(row("Settings", &if keys.is_empty() { dim("none") } else { String::new() }));
            let not_applied = non_string_env_keys(&env_map_of(profile.env.as_ref()).unwrap_or_default());
            for key in keys {
                lines.push(if not_applied.contains(key) {
                    format!("  {} {}", accent(key), dim("(not a string, so not applied - see clm doctor)"))
                } else if hidden.contains(key) {
                    format!("  {} {}", accent(key), dim("(set; not shown - it can hold a credential)"))
                } else {
                    format!("  {}={}", accent(key), map[key].as_str().unwrap_or(""))
                });
            }
        }
    }
    lines.push(String::new());
    lines.push(footer);
    boxed(id, &lines)
}

/// `config --edit`: the env map in $VISUAL or $EDITOR, in a private temp dir.
fn edit_profile_env(id: &str, profile: &Profile) -> Result<String> {
    let current = env_map_of(profile.env.as_ref()).map(Value::Object).or_else(|| profile.env.clone()).unwrap_or(json!({}));
    let editor = [std::env::var("VISUAL").ok(), std::env::var("EDITOR").ok()]
        .into_iter()
        .flatten()
        .find(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow!("Set $EDITOR (or $VISUAL) to use --edit."))?;
    let parts: Vec<String> = regex::Regex::new(r#""([^"]*)"|'([^']*)'|(\S+)"#)
        .unwrap()
        .captures_iter(&editor)
        .map(|c| c.get(1).or(c.get(2)).or(c.get(3)).unwrap().as_str().to_string())
        .collect();
    let (command, editor_args) = parts.split_first().ok_or_else(|| anyhow!("Set $EDITOR (or $VISUAL) to use --edit."))?;
    let dir = std::env::temp_dir().join(format!("clm-env-{}-{}", std::process::id(), util::now_ms()));
    std::fs::create_dir(&dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let scratch = dir.join("env.json");
    let result = (|| -> Result<String> {
        util::write_atomic(&scratch, util::to_pretty(&current).as_bytes(), Some(0o600))?;
        let status = Command::new(command).args(editor_args).arg(&scratch).status().map_err(|e| anyhow!("Could not run {command}: {e}"))?;
        if !status.success() {
            bail!(
                "{command} exited with {}, so nothing was changed.",
                status.code().map(|c| c.to_string()).unwrap_or_else(|| "a signal".into())
            );
        }
        let raw = std::fs::read_to_string(&scratch)?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|_| anyhow!("The edited file is not valid JSON, so nothing was changed."))?;
        let Value::Object(map) = parsed else {
            bail!("The edited file must hold a JSON object of \"KEY\": \"value\" pairs, so nothing was changed.");
        };
        for (k, v) in &map {
            if !v.is_string() {
                bail!("{} must be a string in quotes, so nothing was changed.", shown_env_name(k));
            }
        }
        service::update_profile_env(id, &map, &[], true)?;
        warn_plaintext_env(id, profile, &map.keys().cloned().collect::<Vec<_>>());
        Ok(success(&format!("Updated {} {}", bold(id), dim(&format!("({} setting(s))", map.len())))))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result
}

// ─── Help ───────────────────────────────────────────────────────────

fn usage_text() -> String {
    [
        String::new(),
        format!("  {} {}", bold("clm"), dim("— Claude Code and Codex CLI profile manager")),
        String::new(),
        format!("  {}", bold("USAGE")),
        format!("    clm {}", accent("<command>")),
        String::new(),
        help_section(
            "COMMANDS",
            &[
                ("run <profile>", "Run the CLI with a specific profile"),
                ("init", "Discover accounts and register them"),
                ("add <profile>", "Add a new profile (--api for an endpoint instead of a login)"),
                ("use [profile]", "Switch active profile"),
                ("list", "Show profiles with quota and usage"),
                ("usage [profile]", "Show usage summary"),
                ("current", "Show active profile details"),
                ("config <profile>", "Configure profile settings"),
                ("doctor", "Check profile health"),
                ("repair <profile>", "Repair shared links"),
                ("login <profile>", "Re-authenticate a profile"),
                ("remove <profile>", "Remove a profile"),
                ("uninstall", "Uninstall clm completely"),
                ("shell-init", "Print shell integration"),
                ("version", "Show version"),
            ],
        ),
        String::new(),
        dim("  Note: <profile> is a bare name (e.g. work) or tool:name (e.g. claude:work, codex:personal)"),
        dim("  Run `clm <command> --help` for a command's options."),
        String::new(),
    ]
    .join("\n")
}

fn sub_help(title: &str, desc: &str, usage: &[&str], options: &[(&str, &str)], notes: &[&str]) -> String {
    let mut out = vec![String::new(), format!("  {} {}", accent(title), dim(&format!("— {desc}"))), String::new(), format!("  {}", bold("USAGE"))];
    out.extend(usage.iter().map(|u| help_usage(u)));
    if !options.is_empty() {
        out.push(String::new());
        out.push(format!("  {}", bold("OPTIONS")));
        let w = options.iter().map(|(o, _)| o.len()).max().unwrap_or(0) + 4;
        for (o, d) in options {
            out.push(format!("    {}{}", accent(&pad_plain(o, w)), dim(d)));
        }
    }
    if !notes.is_empty() {
        out.push(String::new());
        out.push(format!("  {}", bold("NOTES")));
        out.extend(notes.iter().map(|n| format!("    {}", dim(n))));
    }
    out.push(String::new());
    out.join("\n")
}

fn subcommand_help(command: &str) -> Option<String> {
    Some(match command {
        "init" => sub_help(
            "clm init",
            "Discover accounts and register them",
            &["clm init [--auto] [--merge-sessions] [--force]"],
            &[
                ("--auto", "Run non-interactively (accept every proposed name)"),
                ("--merge-sessions", "Share session history across profiles (default: separated)"),
                ("--force", "Go ahead while Codex runs in a profile init would move files in"),
            ],
            &[
                "Registers the Claude Code and Codex accounts already signed in; with none,",
                "sign in with `claude login` or `codex login` first. API profiles already",
                "registered are kept. A profiles.json that cannot be read is refused, not replaced.",
            ],
        ),
        "add" => sub_help(
            "clm add",
            "Add a new profile",
            &[
                "clm add <profile> [--from <path>] [--merge-sessions]",
                "clm add <profile> --api --base-url <url> [--model <id>] [--auth <scheme>]",
                "    [--key-from <source>] [--label <name>] [--set KEY=VALUE ...] [--merge-sessions]",
            ],
            &[
                ("--from", "Import configuration from an existing path"),
                ("--merge-sessions", "Share session history across profiles (default: separated)"),
                ("--api", "Create an API profile instead of a subscription login (Claude Code only)"),
                ("--base-url", "API endpoint, http:// or https:// (required with --api); never the key"),
                ("--model", "Model id, stored as ANTHROPIC_MODEL"),
                ("--auth", "bearer | api-key (default: api-key for anthropic.com, else bearer)"),
                ("--key-from", "keychain (default) | env:NAME | command:\"<shell command>\""),
                ("--label", "Display name shown in list (default: the endpoint host)"),
                ("--set", "Advanced setting KEY=VALUE; repeatable"),
            ],
            &[
                "Names: /^[A-Za-z0-9][A-Za-z0-9._-]*$/, compared without case.",
                "The key is read from a prompt that does not echo it, or from stdin:",
                "  printf %s \"$MY_API_KEY\" | clm add claude:gw --api --base-url https://openrouter.ai/api",
                "keychain stores it in the macOS Keychain, or ~/.clm/secrets.json (0600) elsewhere.",
                "Never pass a key as an argument: `ps` shows arguments to every user.",
            ],
        ),
        "use" => sub_help("clm use", "Switch active profile", &["clm use [profile]"], &[], &["Without a profile, asks which one."]),
        "list" => sub_help(
            "clm list",
            "Show profiles with quota and usage",
            &["clm list [--json] [--refresh] [--no-quota] [--no-renew]"],
            &[
                ("--json", "Output as JSON"),
                ("--refresh", "Bypass the 5-minute quota cache"),
                ("--no-quota", "Skip the plan-quota lookup (no network access)"),
                ("--no-renew", "Never renew a lapsed token; report it as expired"),
            ],
            &["An API profile shows its label as ACCOUNT and a dash for 5H and 7D."],
        ),
        "usage" => sub_help(
            "clm usage",
            "Show usage summary",
            &["clm usage [profile] [--period=<period>] [--json]"],
            &[("--period", "<today|week|month|all>  Time period (default: today)"), ("--json", "Output as JSON")],
            &[],
        ),
        "current" => sub_help("clm current", "Show active profile details", &["clm current [--json]"], &[("--json", "Output as JSON")], &[]),
        "doctor" => sub_help(
            "clm doctor",
            "Check profile health",
            &["clm doctor [--json]"],
            &[("--json", "Output as JSON")],
            &[
                "Checks shared links, plugin state, account and stored login for each profile;",
                "for an API profile its endpoint, key source (a command: source is run) and",
                "settings.json overrides. Never prints a key or a key command.",
            ],
        ),
        "config" => sub_help(
            "clm config",
            "Configure profile settings",
            &[
                "clm config <profile> --merge-sessions | --separate-sessions [--force]",
                "clm config <profile> --model <id>",
                "clm config <profile> --set KEY=VALUE [--set ...] [--unset KEY]",
                "clm config <profile> [--base-url <url>] [--auth <scheme>] [--label <name>]",
                "clm config <profile> --key | --key-from <source>",
                "clm config <profile> --edit",
                "clm config <profile> --show [--json]",
            ],
            &[
                ("--merge-sessions", "Share sessions with primary profile"),
                ("--separate-sessions", "Keep sessions isolated (default)"),
                ("--force", "Change session mode while Codex runs in the profile"),
                ("--model", "The model the profile uses, stored as ANTHROPIC_MODEL"),
                ("--set / --unset", "Set or remove an advanced env setting; repeatable"),
                ("--base-url", "Point an API profile at another endpoint"),
                ("--auth", "bearer | api-key: how an API profile presents its key"),
                ("--label", "Name list shows for an API profile"),
                ("--key", "Re-enter the API key (prompt or stdin)"),
                ("--key-from", "keychain | env:NAME | command:\"<shell command>\""),
                ("--edit", "Open the profile's env map in $VISUAL or $EDITOR"),
                ("--show", "Print the profile's settings (--json adds the catalog)"),
            ],
            &["One change per call. --show only reads."],
        ),
        "repair" => sub_help(
            "clm repair",
            "Repair shared links for a profile",
            &["clm repair <profile> [--force]"],
            &[("--force", "Repair a Codex profile while Codex runs in it")],
            &[],
        ),
        "login" => sub_help("clm login", "Re-authenticate a profile", &["clm login <profile>"], &[], &[]),
        "remove" => sub_help(
            "clm remove",
            "Remove a profile",
            &["clm remove <profile>"],
            &[],
            &[
                "The profile's config directory (such as ~/.claude-<name>) and its history stay,",
                "so the name stays taken: delete that directory before adding the name again.",
                "A key clm stored for an API profile is deleted.",
            ],
        ),
        "run" => sub_help(
            "clm run",
            "Run the CLI with a specific profile",
            &["clm run <profile> [-- args...]"],
            &[],
            &["clm run claude:personal -p 'summarize this repo'", "A leading -- is dropped."],
        ),
        "shell-init" => sub_help(
            "clm shell-init",
            "Print shell integration",
            &["clm shell-init"],
            &[],
            &["Add to ~/.zshrc or ~/.bashrc:  eval \"$(clm shell-init)\""],
        ),
        "uninstall" => sub_help(
            "clm uninstall",
            "Uninstall clm completely",
            &["clm uninstall"],
            &[],
            &["Strips links and restores backups for all non-primary profiles; profile dirs stay."],
        ),
        "version" => sub_help("clm version", "Show version", &["clm version"], &[], &[]),
        _ => return None,
    })
}

// ─── Commands ───────────────────────────────────────────────────────

/// `run <profile> [args...]`: the profile's tool with the profile's environment.
pub fn run_profile(profile_arg: &str, args: &[String]) -> Result<i32> {
    let registry = require_registry()?;
    let r = parse_profile_ref(profile_arg, &registry)?;
    let (tool, env, unset) = service::resolve_profile_env(&r.id)?;
    let mut cmd = Command::new(tools::binary(tool));
    cmd.args(args);
    for k in &unset {
        cmd.env_remove(k);
    }
    for (k, v) in &env {
        cmd.env(k, v);
    }
    let status = cmd.status().map_err(|e| anyhow!("could not start {}: {e}", tools::binary(tool)))?;
    if tool == Tool::Claude {
        usage::track_usage(Some(&r.id));
    }
    Ok(status.code().unwrap_or(1))
}

fn has(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

pub fn run_command(command: &str, args: &[String]) -> Result<String> {
    if !matches!(command, "help" | "-h" | "--help") && (has(args, "--help") || has(args, "-h"))
        && let Some(help) = subcommand_help(command) {
            return Ok(help);
        }
    validate_flags(command, args)?;
    let json_out = has(args, "--json");
    match command {
        "help" | "-h" | "--help" => Ok(usage_text()),
        "version" | "-v" | "--version" => Ok(format!("  {} {}", accent("clm"), dim(&format!("v{VERSION}")))),
        "shell-init" => Ok(render_shell_init()),
        "list" => cmd_list(args, json_out),
        "current" => cmd_current(json_out),
        "use" => cmd_use(args),
        "usage" => cmd_usage(args, json_out),
        "doctor" => cmd_doctor(json_out),
        "repair" => {
            let input = args.iter().find(|a| !a.starts_with("--")).ok_or_else(|| anyhow!("Usage: clm repair <profile>"))?;
            let r = parse_profile_ref(input, &require_registry()?)?;
            let n = service::repair_profile(&r.id, has(args, "--force"))?;
            Ok(success(&format!("Repaired {} shared item(s) for {}", bold(&n.to_string()), bold(&r.id))))
        }
        "login" => cmd_login(args),
        "config" => cmd_config(args, json_out),
        "remove" => {
            let input = args.iter().find(|a| !a.starts_with("--")).ok_or_else(|| anyhow!("Usage: clm remove <profile>"))?;
            let r = parse_profile_ref(input, &require_registry()?)?;
            service::remove_profile(&r.id)?;
            Ok(success(&format!("Removed {}", bold(&r.id))))
        }
        "add" => cmd_add(args),
        "init" => cmd_init(args),
        "uninstall" => cmd_uninstall(),
        "run" => bail!("Usage: clm run <profile> [claude-args...]"),
        "_launch" | "_shell-env" => Ok(cmd_launch(args, command == "_launch")),
        "_sync-plugins" => {
            if let Ok(Some(registry)) = load_registry() {
                let primary = registry.primary_source(Tool::Claude).unwrap_or_else(|| tools::default_config_dir(Tool::Claude));
                let dir = std::env::var_os("CLAUDE_CONFIG_DIR").map(PathBuf::from).unwrap_or_else(|| primary.clone());
                links::sync_plugins_json(&dir, &primary);
            }
            Ok(String::new())
        }
        "_track-usage" => {
            usage::track_usage(None);
            Ok(String::new())
        }
        "update" => bail!("This build updates through Cargo: run `cargo install --path .` from its source, or rebuild it."),
        other if other.starts_with('_') => bail!("Unknown command: {other}\n{}", usage_text()),
        _ => Ok(usage_text()),
    }
}

fn cmd_list(args: &[String], json_out: bool) -> Result<String> {
    let items = service::list_profiles(!has(args, "--no-quota"), has(args, "--refresh"), !has(args, "--no-renew"))?;
    if items.is_empty() && load_registry()?.is_none() {
        return Err(no_registry_error());
    }
    if json_out {
        return Ok(serde_json::to_string_pretty(&Value::Array(items.iter().map(|i| i.to_json()).collect()))?);
    }
    Ok(format::render_list(&items))
}

fn cmd_current(json_out: bool) -> Result<String> {
    let registry = require_registry()?;
    let active: Vec<(String, &Profile)> = ALL_TOOLS
        .iter()
        .filter_map(|t| registry.active(*t).and_then(|id| registry.profiles.get(id).map(|p| (id.clone(), p))))
        .collect();
    if active.is_empty() {
        bail!("No active profiles. Run `clm init` to set up profiles.");
    }
    if json_out {
        let mut out = Map::new();
        for (id, p) in &active {
            let mut entry = Map::new();
            entry.insert("id".into(), json!(id));
            entry.extend(redact_profile(p));
            out.insert(p.tool.clone(), Value::Object(entry));
        }
        return Ok(serde_json::to_string_pretty(&out)?);
    }
    let blocks: Vec<String> = active
        .iter()
        .map(|(id, p)| {
            let mut lines = vec![row("Account", &env::profile_display_name(p))];
            if let Some(org) = &p.org_name {
                lines.push(row("Org", org));
            }
            lines.push(row("Config", &dim(&shown_config_path(&p.config_dir))));
            if let Some(model) = env::profile_model(p) {
                lines.push(row("Model", &model));
            }
            if !p.primary() {
                lines.push(row("Sessions", if p.merges() { "merged" } else { "separated" }));
            }
            boxed(id, &lines)
        })
        .collect();
    Ok(blocks.join("\n"))
}

fn cmd_use(args: &[String]) -> Result<String> {
    let registry = require_registry()?;
    let id = match args.first() {
        Some(input) => parse_profile_ref(input, &registry)?.id,
        None => {
            if !util::isatty(0) {
                bail!("Usage: clm use <profile>");
            }
            let ids: Vec<&String> = registry.profiles.keys().collect();
            println!();
            for (i, id) in ids.iter().enumerate() {
                let p = &registry.profiles[*id];
                let active = registry.active(p.tool()).map(|a| a == *id).unwrap_or(false);
                let marker = if active { accent("▸") } else { " ".into() };
                println!("  {marker} {:>2}. {}  {}", i + 1, pad_plain(id, 24), dim(&env::profile_display_name(p)));
            }
            let answer = ask(&format!("\n  Switch to which profile? {} ", accent("(number or name)"))).unwrap_or_default();
            if answer.is_empty() {
                return Ok(dim("  Cancelled."));
            }
            match answer.parse::<usize>() {
                Ok(n) if n >= 1 && n <= ids.len() => ids[n - 1].clone(),
                _ => parse_profile_ref(&answer, &registry)?.id,
            }
        }
    };
    let profile = registry::set_active_profile(&id)?;
    Ok(success(&format!("Switched to {} {}", bold(&id), dim(&format!("({})", env::profile_display_name(&profile))))))
}

fn cmd_usage(args: &[String], json_out: bool) -> Result<String> {
    let input = args.iter().find(|a| !a.starts_with("--"));
    let period = match args.iter().find_map(|a| a.strip_prefix("--period=")) {
        None => UsagePeriod::Today,
        Some(p) => UsagePeriod::parse(p).ok_or_else(|| anyhow!("Invalid --period: use today, week, month or all."))?,
    };
    let id = match input {
        None => None,
        Some(input) => {
            let r = parse_profile_ref(input, &require_registry()?)?;
            if r.tool == Tool::Codex {
                bail!("Usage tracking not supported for codex (yet).");
            }
            Some(r.id)
        }
    };
    let Some(summary) = service::usage_summary(id.as_deref(), period)? else {
        return Ok(success(&dim("No usage data found.")));
    };
    if json_out {
        if id.is_some() {
            return Ok(serde_json::to_string_pretty(&summary[0].1)?);
        }
        let map: Map<String, Value> = summary.iter().map(|(k, s)| (k.clone(), serde_json::to_value(s).unwrap())).collect();
        return Ok(serde_json::to_string_pretty(&map)?);
    }
    Ok(format::render_usage(&summary, id.is_some(), period))
}

fn cmd_doctor(json_out: bool) -> Result<String> {
    if let Some(problem) = registry_problem() {
        bail!(problem);
    }
    let results = service::doctor_profiles()?;
    if json_out {
        return Ok(serde_json::to_string_pretty(&results)?);
    }
    let rendered = format::render_doctor(&results);
    let keys_stored = load_registry()?.is_some_and(|r| {
        r.profiles.values().any(|p| p.is_api() && p.api.as_ref().and_then(|a| a.secret()) == Some(SecretSource::Keychain))
    });
    Ok(if keys_stored { format!("{rendered}  {}\n", dim(&format!("Stored API keys are kept in {}.", secret_store_name()))) } else { rendered })
}

fn cmd_login(args: &[String]) -> Result<String> {
    let input = args.first().ok_or_else(|| anyhow!("Usage: clm login <profile>"))?;
    let r = parse_profile_ref(input, &require_registry()?)?;
    let (profile, status, caveat) = service::login_profile(&r.id)?;
    let caveat = caveat.map(|d| unconfirmed_warning(profile.tool(), &r.id, &d));
    let mut lines = match status {
        LoginStatus::OtherAccount(signed_in_as) => vec![
            format!("  {} {} is signed in as {signed_in_as}, not {}", warn_icon(), r.id, profile.email),
            format!(
                "       {}",
                dim(&format!(
                    "To switch back, sign in to {} in your browser and run {} again",
                    profile.email,
                    accent(&format!("clm login {}", r.id))
                ))
            ),
        ],
        LoginStatus::Unverified => vec![format!("  {} Signed in, but could not read back which account {} now uses", warn_icon(), r.id)],
        LoginStatus::Ok if caveat.is_none() => vec![success(&format!("Token refreshed for {}", bold(&profile.email)))],
        LoginStatus::Ok => vec![],
    };
    lines.extend(caveat);
    Ok(lines.join("\n"))
}

fn cmd_config(args: &[String], json_out: bool) -> Result<String> {
    let set_pairs = option_values(args, "--set")?;
    let unset_keys: Vec<String> = option_values(args, "--unset")?
        .into_iter()
        .map(|k| {
            if util::is_posix_env_name(&k) {
                Ok(k)
            } else {
                Err(anyhow!("Expected --unset to name an environment variable, for example --unset ANTHROPIC_MODEL."))
            }
        })
        .collect::<Result<_>>()?;
    let model_arg = option_value(args, "--model")?;
    let key_from = option_value(args, "--key-from")?;
    let change_key = has(args, "--key") || key_from.is_some();
    let edit = has(args, "--edit");
    let merge = has(args, "--merge-sessions");
    let separate = has(args, "--separate-sessions");
    let base_url = option_value(args, "--base-url")?;
    let auth = option_value(args, "--auth")?;
    let label = option_value(args, "--label")?;
    let change_env = !set_pairs.is_empty() || !unset_keys.is_empty() || model_arg.is_some();
    let change_sessions = merge || separate;
    let change_endpoint = base_url.is_some() || auth.is_some() || label.is_some();

    let pos = positional(args, CONFIG_VALUE_FLAGS);
    let input = pos.first().ok_or_else(|| anyhow!(CONFIG_USAGE))?;
    if pos.len() > 1 {
        bail!(
            "clm config takes one profile and nothing else. --key takes no value: the key is read from a prompt that does not echo it, or from stdin (printf %s \"$KEY\" | clm config <profile> --key)."
        );
    }
    let registry = require_registry()?;
    let r = parse_profile_ref(input, &registry)?;
    let profile = registry.profiles[&r.id].clone();
    let changes = [change_env, change_endpoint, change_key, edit, change_sessions].iter().filter(|b| **b).count();
    if has(args, "--show") {
        if changes > 0 {
            bail!("--show only reads; run the change on its own.");
        }
        return Ok(show_profile(&r.id, &profile, json_out));
    }
    if changes == 0 {
        bail!(CONFIG_USAGE);
    }
    if has(args, "--force") && !change_sessions {
        bail!("--force goes with --merge-sessions or --separate-sessions.");
    }
    if changes > 1 {
        bail!(
            "Change one thing at a time: --model/--set/--unset, --base-url/--auth/--label, --key/--key-from, --edit, or --merge-sessions/--separate-sessions."
        );
    }

    if change_env {
        let mut set = Map::new();
        if let Some(m) = &model_arg {
            if profile.tool() != Tool::Claude {
                bail!("--model sets ANTHROPIC_MODEL, which only Claude Code reads, and '{}' is a Codex profile.", r.id);
            }
            if unset_keys.iter().any(|k| k == "ANTHROPIC_MODEL") {
                bail!(MODEL_TWICE);
            }
            set.insert("ANTHROPIC_MODEL".into(), json!(parse_model(m, false)?));
        }
        for a in &set_pairs {
            let (k, v) = parse_assignment(a, "--set")?;
            if k == "ANTHROPIC_MODEL" && model_arg.is_some() {
                bail!(MODEL_TWICE);
            }
            set.insert(k, json!(v));
        }
        service::update_profile_env(&r.id, &set, &unset_keys, false)?;
        warn_plaintext_env(&r.id, &profile, &set.keys().cloned().collect::<Vec<_>>());
        let before = env_map_of(profile.env.as_ref()).unwrap_or_default();
        let not_set: Vec<&String> = unset_keys.iter().filter(|k| !before.contains_key(*k) && !set.contains_key(*k)).collect();
        let not_set_line = format!(
            "{} {} not set",
            not_set.iter().map(|k| shown_env_name(k)).collect::<Vec<_>>().join(", "),
            if not_set.len() == 1 { "was" } else { "were" }
        );
        let changed: Vec<String> =
            set.keys().chain(unset_keys.iter().filter(|k| !not_set.contains(k))).map(|k| shown_env_name(k)).collect();
        if changed.is_empty() {
            return Ok(dim(&format!("{not_set_line}; nothing changed")));
        }
        let updated = success(&format!("Updated {} {}", bold(&r.id), dim(&format!("({})", changed.join(", ")))));
        return Ok(if not_set.is_empty() { updated } else { format!("{updated}\n  {}", dim(&not_set_line)) });
    }

    if change_endpoint {
        let auth = auth.as_deref().map(parse_auth).transpose()?;
        let result = service::update_profile_api(&r.id, base_url.as_deref(), auth.as_deref(), label.as_deref())?;
        if base_url.is_some() && result.host != result.previous_host {
            let host = result.host.clone().unwrap_or_default();
            let secret = result.profile.api.as_ref().and_then(|a| a.secret());
            let sharers = &result.shared_with;
            let msg = match &secret {
                None => format!(
                    "  {} The key comes from {}, so clm cannot say which key goes to {host} from the next launch.\n    Give it a source clm knows - store the key:\n      {}   {}\n",
                    warn_icon(),
                    key_source_phrase(None),
                    accent(&format!("clm config {} --key", r.id)),
                    dim("(or --key-from env:<NAME>)")
                ),
                Some(SecretSource::Keychain) => format!(
                    "  {} The key is unchanged, so from the next launch it goes to {host}.\n    If this endpoint takes a different key, store it:\n      {}\n",
                    warn_icon(),
                    accent(&format!("clm config {} --key", r.id))
                ),
                Some(s) => {
                    let tail = if sharers.is_empty() {
                        format!(
                            "    If this endpoint takes a different key, {}.\n",
                            if matches!(s, SecretSource::Env(_)) { "set that variable to it" } else { "have the command print it" }
                        )
                    } else {
                        format!(
                            "    {} {} it too, so if this endpoint takes a different key, give this profile its own:\n      {}   {}\n",
                            sharers.join(", "),
                            if sharers.len() == 1 { "reads" } else { "read" },
                            accent(&format!("clm config {} --key-from env:<ANOTHER_NAME>", r.id)),
                            dim("(or --key, to store it)")
                        )
                    };
                    format!(
                        "  {} The key still comes from {}, so from the next launch it goes to {host}.\n{tail}",
                        warn_icon(),
                        key_source_phrase(Some(s))
                    )
                }
            };
            eprint!("{msg}");
        }
        if result.cleartext
            && let Some(h) = &result.host {
                cleartext_note(h);
            }
        if let Some(d) = result.host_default_auth {
            eprint!(
                "  {} {} usually takes {d}, and this profile sends its key as {}.\n    If the endpoint refuses it, switch:\n      {}\n",
                warn_icon(),
                result.host.clone().unwrap_or_default(),
                printable(&result.profile.api.as_ref().map(|a| a.auth_scheme.clone()).unwrap_or_default()),
                accent(&format!("clm config {} --auth {d}", r.id))
            );
        }
        let asked: Vec<&str> = [(base_url.is_some(), "base URL"), (auth.is_some(), "auth"), (label.is_some(), "label")]
            .iter()
            .filter(|(b, _)| *b)
            .map(|(_, s)| *s)
            .collect();
        let followed: Vec<&str> =
            [(result.followed_label, "label"), (result.followed_auth, "auth")].iter().filter(|(b, _)| *b).map(|(_, s)| *s).collect();
        let follows = if followed.is_empty() {
            String::new()
        } else {
            format!("; {} {} the new host", followed.join(" and "), if followed.len() == 1 { "follows" } else { "follow" })
        };
        return Ok(success(&format!("Updated {} {}", bold(&r.id), dim(&format!("({}{follows})", asked.join(", "))))));
    }

    if change_key {
        service::require_endpoint(&r.id, &profile)?;
        let secret = parse_secret_source(key_from.as_deref().unwrap_or("keychain"))?;
        let value = if secret == SecretSource::Keychain { prompt_secret("API key: ")? } else { None };
        if secret == SecretSource::Keychain && value.is_none() {
            bail!(NO_KEY_SUPPLIED);
        }
        let deleted = service::update_profile_secret(&r.id, &secret, value.as_deref())?;
        warn_unset_key_variable(&secret);
        let note = if deleted { format!(" {}", dim(&format!("(deleted the key stored in {})", secret_store_name()))) } else { String::new() };
        return Ok(success(&format!("Updated the credential for {}{note}", bold(&r.id))));
    }

    if edit {
        return edit_profile_env(&r.id, &profile);
    }

    if merge && separate {
        bail!("Pass --merge-sessions or --separate-sessions, not both.");
    }
    if !service::update_session_mode(&r.id, merge, has(args, "--force"))? {
        return Ok(dim(&format!("{} is already {}", r.id, if merge { "merged" } else { "separated" })));
    }
    Ok(success(&format!("{} sessions set to {}", bold(&r.id), if merge { "merged" } else { "separated" })))
}

fn cmd_add(args: &[String]) -> Result<String> {
    let api = has(args, "--api");
    let from = option_value(args, "--from")?;
    let merge = has(args, "--merge-sessions");
    if api && from.is_some() {
        bail!("--api and --from cannot be combined: an API profile has no account to import.");
    }
    if !api
        && let Some(stray) = API_ONLY_FLAGS.iter().find(|f| args.iter().any(|a| a == **f || a.starts_with(&format!("{f}=")))) {
            bail!("{stray} only applies to an API profile. Add --api, or leave it out.");
        }
    let pos = positional(args, ADD_VALUE_FLAGS);
    let input = pos.first().ok_or_else(|| {
        anyhow!(if api { ADD_API_USAGE } else { "Usage: clm add <profile> [--from <path>] [--merge-sessions]" })
    })?;
    let named = input.split_once(':').filter(|(t, _)| Tool::parse(t).is_some());
    if looks_like_credential(named.map(|(_, n)| n).unwrap_or(input)) {
        bail!(CREDENTIAL_AS_NAME_ERROR);
    }
    if pos.len() > 1 {
        bail!(
            "clm add takes one profile name and nothing else. If that was an API key: it is never an argument, so pipe it in (printf %s \"$KEY\" | clm add <profile> --api …) or point at it with --key-from env:NAME."
        );
    }
    let registry = load_registry()?.ok_or_else(no_registry_error)?;
    let (tool, name) = match input.split_once(':') {
        Some((t, n)) => (Tool::parse(t).ok_or_else(|| anyhow!("Unknown tool '{t}'. Use one of: claude, codex."))?, n.to_string()),
        None => {
            let configured: Vec<Tool> = ALL_TOOLS.iter().copied().filter(|t| registry.primary_source(*t).is_some()).collect();
            match configured.len() {
                0 => bail!("No tools configured. Run `clm init` first."),
                1 => (configured[0], input.clone()),
                _ => bail!("Both tools are configured. Specify 'claude:{input}' or 'codex:{input}'."),
            }
        }
    };

    if api {
        if tool != Tool::Claude {
            bail!("API profiles are Claude Code only in this version.");
        }
        let base_url = option_value(args, "--base-url")?.ok_or_else(|| anyhow!(ADD_API_USAGE))?;
        let url = service::parse_base_url(base_url.trim())?;
        let auth = match option_value(args, "--auth")? {
            Some(a) => parse_auth(&a)?,
            None => service::default_auth_scheme(&url_hostname(&url)).to_string(),
        };
        let label = option_value(args, "--label")?;
        if let Some(l) = &label {
            service::check_label(l, true)?;
        }
        let mut env_map = Map::new();
        let model = option_value(args, "--model")?;
        if let Some(m) = &model {
            env_map.insert("ANTHROPIC_MODEL".into(), json!(parse_model(m, true)?));
        }
        for a in option_values(args, "--set")? {
            let (k, v) = parse_assignment(&a, "--set")?;
            if k == "ANTHROPIC_MODEL" && model.is_some() {
                bail!(MODEL_TWICE);
            }
            env::check_model_entry(&k, &v, true)?;
            env::validate_env_entry(&k, &v, true).map_err(|e| anyhow!(e))?;
            env_map.insert(k, json!(v));
        }
        registry::validate_profile_name(&name)?;
        service::free_api_config_dir(&registry, tool, &name)?;
        let secret = parse_secret_source(&option_value(args, "--key-from")?.unwrap_or_else(|| "keychain".into()))?;
        let secret_value = if secret == SecretSource::Keychain { prompt_secret("API key: ")? } else { None };
        if secret == SecretSource::Keychain && secret_value.is_none() {
            bail!(NO_KEY_SUPPLIED);
        }
        let keys: Vec<String> = env_map.keys().cloned().collect();
        let (config_dir, sharers) = service::add_api_profile(
            tool,
            ApiAdd {
                name: name.clone(),
                base_url: base_url.clone(),
                auth_scheme: auth,
                secret: secret.clone(),
                secret_value,
                label,
                env: env_map,
                merge,
            },
        )?;
        let id = profile_id(tool, &name);
        if let Some(profile) = load_registry()?.and_then(|r| r.profiles.get(&id).cloned()) {
            warn_plaintext_env(&id, &profile, &keys);
        }
        warn_unset_key_variable(&secret);
        if sends_key_in_clear(&url) {
            cleartext_note(&url_host(&url));
        }
        if !sharers.is_empty() {
            eprint!(
                "  {} The key comes from {}, which {} {} too for a different endpoint, so one key now goes to {}.\n    If this endpoint takes a key of its own, give this profile its own:\n      {}   {}\n",
                warn_icon(),
                key_source_phrase(Some(&secret)),
                sharers.join(", "),
                if sharers.len() == 1 { "uses" } else { "use" },
                if sharers.len() == 1 { "both" } else { "all of them" },
                accent(&format!("clm config {id} --key-from env:<ANOTHER_NAME>")),
                dim("(or --key, to store it)")
            );
        }
        return Ok(format!(
            "{}\n  {}",
            success(&format!("Added {} {}", bold(&id), dim(&format!("({})", url_host(&url))))),
            dim(&format!("Config: {}", config_dir.display()))
        ));
    }

    let added = service::add_profile(tool, &name, from.as_deref(), merge)?;
    for w in &added.warnings {
        warn_line(w);
    }
    let id = profile_id(tool, &name);
    let line = success(&format!("Added {} {}", bold(&id), dim(&format!("({})", added.email))));
    Ok(match added.credential_unconfirmed {
        None => line,
        Some(d) => format!("{line}\n{}", unconfirmed_warning(tool, &id, &d)),
    })
}

fn cmd_init(args: &[String]) -> Result<String> {
    let imported = registry::import_legacy()?;
    if !imported.is_empty() {
        println!("  {} Imported {} from ~/.clausona into ~/.clm {}", ok_icon(), imported.join(", "), dim("(~/.clausona is left as it is)"));
    }
    let accounts = service::discover_accounts();
    if accounts.is_empty() {
        bail!("No Claude Code or Codex accounts found. Sign in with `claude login` or `codex login` first.");
    }
    let existing = load_registry()?;
    let mut merge = has(args, "--merge-sessions");
    let mut chosen = std::collections::HashMap::new();
    let mut default_profile = None;
    let interactive = !has(args, "--auto") && util::isatty(0) && util::isatty(1);
    if interactive {
        let proposed = service::propose_init_names(&accounts, existing.as_ref(), &chosen);
        println!("\n  {}\n", bold("Accounts found on this machine"));
        for a in &accounts {
            println!(
                "    {} {}  {}{}",
                accent(&pad_plain(a.tool.name(), 7)),
                pad_plain(&a.email, 32),
                dim(&shown_config_path(&a.config_dir.to_string_lossy())),
                if a.is_primary { dim("  (primary)") } else { String::new() }
            );
        }
        println!("\n  {}", dim("Name each profile (Enter keeps the proposed name)."));
        for a in &accounts {
            let proposal = &proposed[&a.config_dir];
            let answer = ask(&format!("    {} {} [{}]: ", a.tool, a.email, accent(proposal))).unwrap_or_default();
            if !answer.is_empty() {
                registry::validate_profile_name(&answer)?;
                chosen.insert(a.config_dir.clone(), answer);
            }
        }
        if !merge && accounts.iter().any(|a| !a.is_primary) {
            let answer = ask(&format!("\n  Share session history across profiles? {} ", accent("(y/N)"))).unwrap_or_default();
            merge = matches!(answer.to_lowercase().as_str(), "y" | "yes");
        }
        let names = service::propose_init_names(&accounts, existing.as_ref(), &chosen);
        let claude: Vec<&String> = accounts.iter().filter(|a| a.tool == Tool::Claude).map(|a| &names[&a.config_dir]).collect();
        if claude.len() > 1 {
            let answer = ask(&format!(
                "  Active claude profile? {} [{}]: ",
                dim(&claude.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
                accent(claude[0])
            ))
            .unwrap_or_default();
            default_profile = Some(if answer.is_empty() { claude[0].clone() } else { answer });
        }
        chosen = names;
    }
    service::initialize_registry(&accounts, InitOptions { names: chosen, default_profile, merge_sessions: merge, force: has(args, "--force") })?;
    for a in &accounts {
        for w in service::configdir_warnings(a.tool, &a.config_dir) {
            warn_line(&w);
        }
    }
    let mut out = success(&format!("Initialized {} profile(s)", bold(&accounts.len().to_string())));
    let rc_hooked = ["zshrc", "bashrc"].iter().any(|rc| {
        util::read_text(&home().join(format!(".{rc}"))).is_some_and(|c| c.contains("clm shell-init"))
    });
    if !rc_hooked {
        out.push_str(&format!(
            "\n  {}\n    {}",
            dim("Add the shell hook so `claude` and `codex` follow `clm use`:"),
            accent("echo 'eval \"$(clm shell-init)\"' >> ~/.zshrc")
        ));
    }
    Ok(out)
}

fn cmd_uninstall() -> Result<String> {
    println!(
        "\n  {}\n    {}\n    {}\n    {}\n    {}\n    {}\n",
        bold("This will completely uninstall clm:"),
        dim("• Strip symlinks and restore backups for all non-primary profiles"),
        dim("• Profile directories at ~/.claude-<name> are preserved (data intact)"),
        dim("• Remove shell integration from rc files"),
        dim("• Delete ~/.clm/ (registry, usage), keeping any backup that could not be put back"),
        dim("• Delete this binary")
    );
    let answer = ask(&format!("  Proceed? {} ", accent("(y/N)"))).unwrap_or_default();
    if answer.to_lowercase() != "y" {
        return Ok(dim("  Cancelled."));
    }
    let removed = service::uninstall();
    if removed.is_empty() {
        return Ok(success(&dim("Nothing to uninstall.")));
    }
    let mut lines = vec![success("clm has been uninstalled."), String::new()];
    lines.extend(removed.iter().map(|r| format!("  {} {}", dim("•"), dim(r))));
    lines.push(String::new());
    lines.push(dim("  Open a new terminal to clear the shell integration."));
    Ok(lines.join("\n"))
}

/// `_launch <tool>`: the script the hook evals. stdout carries the script and nothing else;
/// every warning goes to stderr, on every launch, until the profile is fixed.
fn cmd_launch(args: &[String], marker: bool) -> String {
    let empty = if marker { LAUNCH_MARKER.to_string() } else { String::new() };
    let Some(tool) = args.iter().find(|a| !a.starts_with('-')).and_then(|t| Tool::parse(t)) else { return empty };
    let Ok(Some(registry)) = load_registry() else { return empty };
    let Some(id) = registry.active(tool).cloned() else { return empty };
    let Some(profile) = registry.profiles.get(&id) else { return empty };
    let built = env::build_profile_env(&id, profile);
    for w in &built.warnings {
        warn_line(w);
    }
    let guard = controlled_env_keys(profile, &built);
    if tool == Tool::Claude && marker {
        let primary = registry.primary_source(Tool::Claude).unwrap_or_else(|| tools::default_config_dir(Tool::Claude));
        let dir = built.env.get("CLAUDE_CONFIG_DIR").map(PathBuf::from).unwrap_or_else(|| primary.clone());
        links::sync_plugins_json(&dir, &primary);
    }
    let exports = render_posix_exports(&built.env, &built.unset, &guard);
    if !marker {
        return exports;
    }
    if exports.is_empty() { LAUNCH_MARKER.to_string() } else { format!("{LAUNCH_MARKER}\n{exports}") }
}
