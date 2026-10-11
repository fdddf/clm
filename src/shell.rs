//! The shell hook, and the launch script it evaluates before each `claude` or `codex`.
//!
//! The Node version cached each launch script so the common path started no Node process;
//! this binary starts in a few milliseconds, so the hook simply asks `clm _launch` every
//! time and there is no cache to keep in step with profiles.json.

use indexmap::IndexMap;

use crate::util::{is_posix_env_name, posix_quote};

/// The first line of every launch script, and the only thing the hook evals.
pub const LAUNCH_MARKER: &str = "# clm launch";

/// A guard over every name the profile must control, then the unsets, then the exports.
/// An API profile launches only if every name it sets or clears lands exactly as it says,
/// so a `readonly` variable in the user's shell stops the launch rather than leaking.
pub fn render_posix_exports(env: &IndexMap<String, String>, unset: &[String], guard: &[String]) -> String {
    let cleared: Vec<&String> = unset.iter().filter(|k| is_posix_env_name(k)).collect();
    let mut controlled: Vec<&String> = Vec::new();
    for k in cleared.iter().copied().chain(guard.iter().filter(|k| is_posix_env_name(k))) {
        if !controlled.contains(&k) {
            controlled.push(k);
        }
    }
    let mut lines = Vec::new();
    if !controlled.is_empty() {
        let names = controlled.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
        lines.push(format!(
            "if ( unset {names} ) 2>/dev/null; then :; else for _clausona_name in {names}; do ( unset $_clausona_name ) 2>/dev/null || printf 'clm: %s is read-only in this shell, so clm cannot set or clear it for this profile. Not starting the tool.\\n' $_clausona_name >&2; done; exit 1; fi"
        ));
    }
    if !cleared.is_empty() {
        lines.push(format!("unset {}", cleared.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")));
    }
    for (k, v) in env {
        if is_posix_env_name(k) {
            lines.push(format!("export {k}={}", posix_quote(v)));
        }
    }
    lines.join("\n")
}

/// The zsh/bash integration `eval "$(clm shell-init)"` installs. The tool runs in a
/// subshell, so the profile's variables live exactly as long as it does; after claude exits,
/// usage is recorded in the background, outside the shell's job table.
pub fn render_shell_init() -> String {
    let marked = format!("{}*", posix_quote(LAUNCH_MARKER));
    let launch = |tool: &str| {
        format!(
            r#"    _clausona_launch=$(clm _launch {tool}) || :
    if [[ $_clausona_launch == {marked} ]]; then
      eval "$_clausona_launch"
    elif [[ -n $_clausona_launch ]]; then
      printf 'clm: unexpected output from clm _launch; starting {tool} without a profile\n' >&2
    fi"#
        )
    };
    format!(
        r#"# clm shell integration
unalias claude 2>/dev/null
claude() {{
  # An explicit CLAUDE_CONFIG_DIR means the user is driving; clm steps aside.
  if [[ -n "${{CLAUDE_CONFIG_DIR:-}}" ]]; then
    command claude "$@"
    return $?
  fi
  (
{claude}
    command claude "$@"
  )
  local rc=$?
  ( clm _track-usage </dev/null >/dev/null 2>&1 & )
  return $rc
}}

unalias codex 2>/dev/null
codex() {{
  if [[ -n "${{CODEX_HOME:-}}" ]]; then
    command codex "$@"
    return $?
  fi
  (
{codex}
    command codex "$@"
  )
  return $?
}}

"#,
        claude = launch("claude"),
        codex = launch("codex"),
    )
}
