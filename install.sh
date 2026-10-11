#!/bin/sh
# Installs clm from its GitHub release:
#
#   curl -fsSL https://raw.githubusercontent.com/fdddf/clm/main/install.sh | sh
#
# Environment:
#   CLM_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   CLM_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   CLM_NO_HOOK=1    do not add `eval "$(clm shell-init)"` to your shell rc file

set -eu

REPO="fdddf/clm"
INSTALL_DIR="${CLM_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${CLM_VERSION:-latest}"

say() { printf '  %s\n' "$*"; }
fail() { printf '  error: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
need uname
need tar
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  fail "curl or wget is required"
fi

case "$(uname -s)" in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-musl ;;
  *) fail "unsupported system $(uname -s): clm runs on macOS and Linux" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac
# A shell under Rosetta reports x86_64 on an Apple Silicon Mac; the native build is better.
if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  arch=aarch64
fi
target="$arch-$os"
asset="clm-$target.tar.gz"

if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || fail "could not download $base/$asset"
fetch "$base/$asset.sha256" "$tmp/$asset.sha256" || fail "could not download the checksum for $asset"

expected="$(awk '{print $1}' "$tmp/$asset.sha256")"
if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
elif command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  fail "shasum or sha256sum is required to check the download"
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset; nothing was installed"

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
# Replaced by a rename, so a clm that is running keeps its own copy.
cp "$tmp/clm-$target/clm" "$INSTALL_DIR/.clm.new"
chmod 755 "$INSTALL_DIR/.clm.new"
mv -f "$INSTALL_DIR/.clm.new" "$INSTALL_DIR/clm"
say "Installed $("$INSTALL_DIR/clm" --version 2>/dev/null | sed 's/^ *//') to $INSTALL_DIR/clm"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) on_path=1 ;;
  *) on_path=0 ;;
esac

case "${SHELL:-}" in
  */zsh) rc="$HOME/.zshrc" ;;
  */bash) if [ "$(uname -s)" = Darwin ]; then rc="$HOME/.bash_profile"; else rc="$HOME/.bashrc"; fi ;;
  *) rc="" ;;
esac

if [ "${CLM_NO_HOOK:-}" != 1 ] && [ -n "$rc" ]; then
  if [ -f "$rc" ] && grep -q 'clm shell-init' "$rc"; then
    say "Shell hook already in $rc"
  else
    {
      printf '\n# clm: switch Claude Code / Codex accounts\n'
      if [ "$on_path" = 0 ]; then printf 'export PATH="%s:$PATH"\n' "$INSTALL_DIR"; fi
      printf 'eval "$(clm shell-init)"\n'
    } >>"$rc"
    say "Added the shell hook to $rc"
  fi
  say "Open a new terminal (or run: source $rc), then: clm init"
else
  [ "$on_path" = 1 ] || say "Add $INSTALL_DIR to your PATH."
  say "Add this to your shell rc file:  eval \"\$(clm shell-init)\""
  say "Then open a new terminal and run: clm init"
fi
