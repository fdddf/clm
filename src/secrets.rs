//! Where an API profile's key lives: the macOS Keychain, `~/.clm/secrets.json`
//! elsewhere, or a reference to an environment variable or a command.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

use crate::checks::carries_credential_token;
use crate::types::SecretSource;
use crate::util::{data_dir, is_posix_env_name, write_json};

fn secrets_path() -> std::path::PathBuf {
    data_dir().join("secrets.json")
}

pub fn keychain_item_for(profile_id: &str) -> String {
    format!("clm-{profile_id}")
}

/// The item the original clausona stored a key under. Read when clm has none of its own, so
/// an imported API profile keeps working; never written or deleted, since it is clausona's.
fn legacy_keychain_item_for(profile_id: &str) -> String {
    format!("clausona-{profile_id}")
}

fn uses_keychain() -> bool {
    cfg!(target_os = "macos")
}

pub fn secret_store_name() -> &'static str {
    if uses_keychain() { "the macOS Keychain" } else { "~/.clm/secrets.json" }
}

/// Runs a command with stderr discarded, feeding `input` on stdin. (exit code, stdout)
pub fn run_capture(program: &str, args: &[&str], input: Option<&str>) -> (i32, String) {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
    let Ok(mut child) = cmd.spawn() else {
        return (1, String::new());
    };
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        let _ = stdin.write_all(text.as_bytes());
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
    (code, out)
}

fn read_secrets_file() -> Result<Map<String, Value>> {
    let path = secrets_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => bail!("could not read {}: {e}", path.display()),
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => bail!("{} must contain a JSON object", path.display()),
        Err(_) => bail!("{} is not valid JSON - fix or remove it", path.display()),
    }
}

fn write_secrets_file(values: Map<String, Value>) -> Result<()> {
    write_json(&secrets_path(), &Value::Object(values), Some(0o600))?;
    Ok(())
}

/// The longest line `security -i` reads.
const SECURITY_MAX_LINE: usize = 4094;

fn security_line_arg(value: &str) -> Result<String> {
    if value.contains('\n') || value.contains('\0') {
        bail!("could not write the Keychain item: its name has a line break or a NUL in it");
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn add_generic_password_line(service: &str, account: &str, hex: &str) -> Result<String> {
    Ok(format!(
        "add-generic-password -U -s {} -a {} -X {hex}",
        security_line_arg(service)?,
        security_line_arg(account)?
    ))
}

/// What `security find-generic-password -w` prints for a value: as-is when it is printable
/// ASCII, as hex otherwise.
fn printed_password(value: &str) -> String {
    if value.bytes().all(|b| (0x20..=0x7e).contains(&b)) { format!("{value}\n") } else { format!("{}\n", hex::encode(value)) }
}

/// Writes a Keychain item and reads it back. The value goes to `security` on stdin, never in
/// its arguments, where `ps` would show it to every user on the machine.
pub fn write_keychain_item(service: &str, account: &str, value: &str) -> Result<()> {
    let hex = hex::encode(value);
    let line = add_generic_password_line(service, account, &hex)?;
    let (code, _) = if line.len() <= SECURITY_MAX_LINE {
        run_capture("security", &["-i"], Some(&format!("{line}\n")))
    } else {
        run_capture("security", &["add-generic-password", "-U", "-s", service, "-a", account, "-X", &hex], None)
    };
    if code != 0 {
        bail!("could not write Keychain item '{service}'");
    }
    let (code, out) = run_capture("security", &["find-generic-password", "-s", service, "-a", account, "-w"], None);
    if code != 0 || out != printed_password(value) {
        bail!("Keychain item '{service}' did not take the new value");
    }
    Ok(())
}

pub fn store_secret(profile_id: &str, value: &str) -> Result<()> {
    if uses_keychain() {
        let service = keychain_item_for(profile_id);
        let line = add_generic_password_line(&service, profile_id, &hex::encode(value))?;
        if line.len() > SECURITY_MAX_LINE {
            bail!(
                "the key is too long to store in the Keychain - keep it elsewhere and point at it with --key-from env:NAME or --key-from command:\"<command>\""
            );
        }
        return write_keychain_item(&service, profile_id, value);
    }
    let mut values = read_secrets_file()?;
    values.insert(profile_id.to_string(), Value::String(value.to_string()));
    write_secrets_file(values)
}

/// True when a stored key was there to delete.
pub fn delete_secret(profile_id: &str) -> Result<bool> {
    if uses_keychain() {
        let (code, _) = run_capture("security", &["delete-generic-password", "-s", &keychain_item_for(profile_id)], None);
        return Ok(code == 0);
    }
    let mut values = read_secrets_file()?;
    if values.remove(profile_id).is_none() {
        return Ok(false);
    }
    write_secrets_file(values)?;
    Ok(true)
}

fn read_stored_secret(profile_id: &str) -> Result<Option<String>> {
    if uses_keychain() {
        for service in [keychain_item_for(profile_id), legacy_keychain_item_for(profile_id)] {
            let (code, out) = run_capture("security", &["find-generic-password", "-s", &service, "-w"], None);
            let trimmed = out.trim();
            if code == 0 && !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
        return Ok(None);
    }
    Ok(read_secrets_file()?.get(profile_id).and_then(|v| v.as_str()).map(String::from))
}

/// The key itself. No error carries it.
pub fn resolve_secret(profile_id: &str, source: Option<&SecretSource>) -> Result<String> {
    match source {
        None => Err(anyhow!(
            "the key source in ~/.clm/profiles.json is not keychain, env or command, so no key was read - run 'clm config {profile_id} --key' to store one, or 'clm config {profile_id} --key-from env:<NAME>' to read one"
        )),
        Some(SecretSource::Env(name)) => {
            if !is_posix_env_name(name) {
                bail!("the key's environment variable is not a valid name - run 'clm config {profile_id} --key-from env:<NAME>'");
            }
            match std::env::var(name) {
                Ok(v) if !v.is_empty() => Ok(v),
                _ if carries_credential_token(name) => Err(anyhow!(
                    "the key's environment variable is unset, and its name looks like an API key - run 'clm config {profile_id} --key-from env:<NAME>' with the name of the variable that holds the key"
                )),
                _ => Err(anyhow!("environment variable {name} is unset or empty")),
            }
        }
        Some(SecretSource::Command(run)) => {
            let (code, out) = run_capture("/bin/sh", &["-c", run], None);
            let remedy = format!(
                "run it yourself to see why - it is in ~/.clm/profiles.json - or replace it with 'clm config {profile_id} --key-from command:\"<command>\"'"
            );
            if code != 0 {
                bail!("secret command exited with {code} - {remedy}");
            }
            let first = out.lines().next().unwrap_or("").trim().to_string();
            if first.is_empty() {
                bail!("secret command produced no output - {remedy}");
            }
            Ok(first)
        }
        Some(SecretSource::Keychain) => read_stored_secret(profile_id)?
            .ok_or_else(|| anyhow!("no stored secret for '{profile_id}' - run 'clm config {profile_id} --key'")),
    }
}

/// Reads a key from a prompt that does not echo it, or from stdin when something is piped in.
/// The ends are trimmed; one with a space, a line break or a non-ASCII character inside is
/// refused.
pub fn prompt_secret(prompt: &str) -> Result<Option<String>> {
    let raw = if crate::util::isatty(0) {
        rpassword::prompt_password(prompt).unwrap_or_default()
    } else {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).ok();
        buf
    };
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Ok(None);
    }
    if key.chars().any(|c| c.is_whitespace()) {
        bail!("The key has a space or a line break inside it, so it was not stored: an API key has neither.");
    }
    if key.chars().any(|c| !(' '..='~').contains(&c)) {
        bail!(
            "The key has a character outside printable ASCII - an invisible space, an accent or a curly quote copied along with it - so it was not stored."
        );
    }
    Ok(Some(key))
}
