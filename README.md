# clm

**Switch between multiple Claude Code and OpenAI Codex CLI accounts on one machine. Each account signs in on its own; plugins, skills and settings are shared.**

`clm` is a Rust port of [clausona](https://github.com/larcane97/clausona): a single binary that starts in about 8 ms, needs no Node.js, and imports an existing clausona setup.

```bash
clm use work            # claude now starts as the work account
clm use codex:personal  # codex now starts as the personal account
clm list                # every account's 5-hour and 7-day plan quota
```

## Why

With personal, work or per-organization Claude Code and Codex accounts on one machine:

- **Switching is manual.** You log out and back in, or juggle `CLAUDE_CONFIG_DIR` / `CODEX_HOME` yourself.
- **Settings don't carry over.** A second account gets an empty config directory, so plugins, permissions and skills are set up again and drift apart afterwards.

`clm` gives each account a config directory for its sign-in and history, and links everything else to your primary directory. Set it up once and every account has it.

## Features

- **One-command switching**: `clm use <name>`, and the next `claude` or `codex` runs as that account.
- **Shared environment**: for Claude Code, plugins (and the MCP servers they bring), `settings.json` with its hooks and permissions, skills, commands and agents; for Codex, `config.toml`, skills, plugins and hooks. Shared across the accounts of each tool.
- **Shared history, if you want it**: after `clm config <profile> --merge-sessions`, `claude --resume` / `--continue` (and `codex resume` on macOS and Linux) find conversations from every account that shares history.
- **Plan quota at a glance**: 5-hour and weekly usage for every account, read from each tool's own usage endpoint. Lapsed tokens are renewed on demand.
- **Two accounts at once**: `clm run claude:personal` starts one session under another account without switching.
- **API profiles**: a profile can point at the Anthropic API, a gateway such as OpenRouter, or a model you serve yourself, instead of a subscription login (Claude Code only).
- **Pure passthrough**: the shell hook sets the profile's environment for one run and executes the real `claude` / `codex`. No daemon, no proxy, no server.
- **Usage tracking**: per-profile cost and tokens, recorded locally (Claude Code only).
- **Health checks**: `clm doctor` checks links, sign-ins and API configuration; `clm repair` fixes links.

## Install

macOS and Linux (x86_64 and arm64), zsh or bash. You need at least one of [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or the [Codex CLI](https://github.com/openai/codex).

```bash
curl -fsSL https://raw.githubusercontent.com/fdddf/clm/main/install.sh | sh
```

The installer downloads the prebuilt binary for your platform from the [latest release](https://github.com/fdddf/clm/releases/latest), checks it against the published SHA-256, puts it in `~/.local/bin`, and adds `eval "$(clm shell-init)"` to your `~/.zshrc` (or bash rc file). Open a new terminal afterwards. Running it again updates clm.

| Variable | Effect |
| --- | --- |
| `CLM_VERSION=v0.1.0` | Install that release instead of the latest |
| `CLM_INSTALL_DIR=/usr/local/bin` | Install somewhere else |
| `CLM_NO_HOOK=1` | Leave your rc file alone |

```bash
curl -fsSL https://raw.githubusercontent.com/fdddf/clm/main/install.sh | CLM_NO_HOOK=1 sh
```

From source instead (Rust 1.88+):

```bash
cargo install --git https://github.com/fdddf/clm
echo 'eval "$(clm shell-init)"' >> ~/.zshrc    # ~/.bashrc for bash
```

## Quick start

`clm` starts from an account that is already signed in. If none is, run `claude login` or `codex login` once first.

```bash
clm init                 # discover signed-in accounts and register them (--auto: no questions)
clm add claude:work      # create ~/.claude-work and run Claude Code's own sign-in
clm add codex:work       # create ~/.codex-work and run codex login
clm use work             # a bare name works when it is unique across tools
clm use codex:personal
clm list                 # accounts, quota and this week's usage
```

## Plan quota

```
    PROFILE             ACCOUNT                         5H         7D
  ▸ claude:work         you@example.com                 6% 23m     46% 13h
    claude:personal     you@personal.com                0%         100% 4d
  ▸ codex:work          you@example.com                 —          12% 5d
```

`5H` is the rolling session window and `7D` the weekly one, each followed by the time until it resets. Readings come from each tool's own usage endpoint, using the credential that tool stored for the profile, and are cached for 5 minutes. `--refresh` forces a re-read, `--no-quota` skips the network entirely, and `--no-renew` never renews a lapsed token.

A dash means no reading, with the reason listed below the table: `expired` (sign-in lapsed; run `clm login <profile>`), `missing` (no stored credential), `cooldown` (the endpoint is rate limiting), `error` (network or parse failure). API profiles bill per token and have no plan window, so they always show a dash.

## API profiles

```bash
# a hosted gateway; the key is read from a prompt that does not echo it, or from stdin
printf %s "$KEY" | clm add claude:gw --api --base-url https://openrouter.ai/api --model z-ai/glm-5.3

# a model you serve yourself, with the key read from an environment variable
clm add claude:local --api --base-url http://localhost:8000 --model glm-5.3 \
  --key-from env:MY_KEY \
  --set CLAUDE_CODE_MAX_CONTEXT_TOKENS=262144 --set API_TIMEOUT_MS=600000
```

- The key is **never a command-line argument**, since `ps` shows every process's arguments to every user. `--key-from` picks where it lives:
  - `keychain` (default): the macOS Keychain on a Mac, `~/.clm/secrets.json` (mode 0600) elsewhere.
  - `env:NAME`: only the variable name is stored; it is read at each launch from the shell that runs `claude`.
  - `command:"op read …"`: the command runs at each launch and its first output line is the key.
- `--auth`: `api-key` (sent as `ANTHROPIC_API_KEY`, the default for `anthropic.com`) or `bearer` (sent as `ANTHROPIC_AUTH_TOKEN`, the default elsewhere).
- Launching an API profile clears every credential and routing variable inherited from your shell (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_USE_BEDROCK` and the rest) unless the profile sets it. If one of them is read-only in your shell, the launch is refused rather than started with the wrong credential.
- An `api-key` profile's first session asks "Do you want to use this API key?" — answer **Yes**.

Change it later:

```bash
clm config claude:gw --model z-ai/glm-5.3-flash
clm config claude:gw --base-url http://localhost:8000      # the key is kept; clm says where it now goes
printf %s "$NEW_KEY" | clm config claude:gw --key
clm config claude:gw --key-from env:OTHER_KEY
clm config claude:gw --show [--json]                       # never prints the key
```

## Commands

`<profile>` is a bare name (`work`) when it is unique, or `tool:name` (`claude:work`, `codex:work`).

| Command | Description |
| --- | --- |
| `clm init [--auto] [--merge-sessions]` | Discover and register signed-in accounts; the first run imports `~/.clausona` |
| `clm add <profile> [--from <path>] [--merge-sessions]` | Add and sign in a profile, or import an existing directory |
| `clm add <profile> --api --base-url <url> [...]` | Add an API profile |
| `clm use [profile]` | Switch the active profile (asks when none is given) |
| `clm run <profile> [-- args...]` | Run the tool once under a profile, without switching |
| `clm list [--json] [--refresh] [--no-quota] [--no-renew]` | List profiles with quota and usage |
| `clm current [--json]` | Show the active profiles |
| `clm usage [profile] [--period=today\|week\|month\|all]` | Cost and token usage |
| `clm config <profile> --merge-sessions \| --separate-sessions` | Share or separate session history |
| `clm config <profile> --model <id> \| --set K=V \| --unset K \| --edit` | Per-profile environment settings |
| `clm config <profile> --base-url \| --auth \| --label \| --key \| --key-from` | Change an API profile |
| `clm config <profile> --show [--json]` | Show settings (`--json` adds the settings catalog) |
| `clm doctor [--json]` | Check every profile |
| `clm repair <profile> [--force]` | Fix shared links |
| `clm login <profile>` | Sign in again |
| `clm remove <profile>` | Remove a profile (its config directory and history stay) |
| `clm uninstall` | Uninstall clm |

Every command takes `--help`.

## How it works

`clm use` only records which profile is active. The shell hook wraps `claude` and `codex`: each launch runs `clm _launch <tool>` for the profile's environment (`CLAUDE_CONFIG_DIR` or `CODEX_HOME`, and for an API profile its endpoint and key), applies it in a subshell and runs the real binary, so your interactive shell is left as it was. After `claude` exits, usage is recorded in the background.

If you export `CLAUDE_CONFIG_DIR` or `CODEX_HOME` yourself, the hook steps aside.

A profile keeps its sign-in and history; everything else links to the primary:

```
~/.claude-work/
├── .claude.json        ← own account metadata and `claude mcp add` servers (not shared)
├── .credentials.json   ← own OAuth tokens (not shared; in the Keychain on macOS)
├── projects/           ← own session history (not shared by default)
├── plugins/            ← own directory; each entry links to the primary's, and the two
│                         JSON files that hold paths are per-profile copies
├── settings.json  →  ~/.claude/settings.json
└── skills/        →  ~/.claude/skills
```

Codex is the other way round: a profile links only an allowlist of configuration (`config.toml`, `*.config.toml`, `hooks.json`, `AGENTS*.md`, `rules/`, `skills/`, `plugins/`, `agents/`, `prompts/` and a few more). Everything else stays with the account, including the app-server daemon, memories and SQLite databases. With merged sessions, the session history and the thread store (`state_5.sqlite`, `goals_1.sqlite`, `thread_history_1.sqlite`) are shared as one unit.

Nothing is deleted: whatever stands where a link goes is moved to `~/.clm/backups/<tool>/<profile>/<name>.<timestamp>` first, and put back when the profile is removed.

## Data and clausona compatibility

`clm` keeps its data in `~/.clm/`:

```
~/.clm/
├── profiles.json   # profiles and active selection (an API profile's key source, never the key)
├── secrets.json    # stored API keys on Linux (the Keychain on macOS)
├── usage.json      # per-profile usage history
├── quota.json      # cached quota readings (5 minutes)
├── locks/
└── backups/
```

The format is clausona's `~/.clausona/`:

- The first `clm init`, when there is no `~/.clm/` yet but there is a `~/.clausona/`, **copies** clausona's registry, usage history, quota cache, file-stored keys and backups. `~/.clausona/` is only read, so clausona keeps working. After that the two are independent.
- macOS Keychain: new keys are stored as `clm-<tool>:<name>`; when there is none, clausona's `clausona-<tool>:<name>` is read, so imported API profiles work as they are.
- Profile directories (`~/.claude-<name>`, `~/.codex-<name>`) are the tools' own config directories, used by both.
- Coming from clausona, replace `eval "$(clausona shell-init)"` in your rc file with `eval "$(clm shell-init)"`. Don't load both.

`clm` has no telemetry and no server. Its only network calls are each profile's quota lookup and token renewal, sent to that profile's own provider (`api.anthropic.com` or `chatgpt.com`); `--no-quota` skips them.

## Differences from clausona

- The command is `clm`; there is no `csn` alias.
- No TUI dashboard: bare `clm` prints help, and `init` and `use` without a profile ask in the terminal.
- No launch cache: `_launch` takes about 8 ms, so the hook calls it every time.
- No Windows / PowerShell support.
- No `update` command; run the install script again to update.
- Running `init` again keeps usage history.
- Plugin sync reads the primary's `known_marketplaces.json` first, so a marketplace's `source` is not lost.
- The fleet plugins (Superset, herdr, Orca) are not ported.

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets
```

Pushing a `v*` tag builds static binaries for macOS and Linux (x86_64 and arm64) and publishes them, with their checksums and `install.sh`, as a GitHub release.

## License

MIT. Ported from [larcane97/clausona](https://github.com/larcane97/clausona) (MIT); see [LICENSE](LICENSE).
