#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Package Warden — Package Manager Setup
#
# Configures your package managers to route through Package Warden proxy.
# Run this script after starting Package Warden.
#
# Usage:
#   ./setup-package-managers.sh          # configure all available
#   ./setup-package-managers.sh --undo   # restore original settings
#
# Environment variables:
#   PW_PORT   Port Package Warden is listening on (default: 5050)
#
# Package managers configured:
#   npm, pip, dotnet/NuGet, cargo, go modules, bundler
# ---------------------------------------------------------------------------

PW_PORT="${PW_PORT:-5050}"
BASE="http://localhost:${PW_PORT}"
UNDO=false
COUNT_OK=0
COUNT_SKIP=0

for arg in "$@"; do
    case "$arg" in
        --undo)      UNDO=true ;;
        --port=*)    PW_PORT="${arg#--port=}"; BASE="http://localhost:${PW_PORT}" ;;
        -h|--help)
            grep '^#' "$0" | head -20 | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ok()   { echo "  [+] $*"; COUNT_OK=$((COUNT_OK + 1)); }
_skip() { echo "  [-] $*"; COUNT_SKIP=$((COUNT_SKIP + 1)); }
_info() { echo "      $*"; }
_has()  { command -v "$1" &>/dev/null; }

# Remove lines between package-warden markers in a file.
_strip_markers() {
    local file="$1" marker="$2"
    if [ ! -f "$file" ]; then return; fi
    local tmpf; tmpf=$(mktemp)
    sed "/# --- package-warden:${marker} start ---/,/# --- package-warden:${marker} end ---/d" "$file" > "$tmpf"
    mv "$tmpf" "$file"
    # Drop trailing blank lines introduced by the removal.
    sed -i.bak -e '/^[[:space:]]*$/{N; /^\n[[:space:]]*$/d;}' "$file" && rm -f "${file}.bak" || true
}

# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

setup_npm() {
    if ! _has npm; then _skip "npm — not installed"; return; fi
    if $UNDO; then
        npm config delete registry 2>/dev/null || true
        _ok "npm — registry restored to default"
    else
        npm config set registry "${BASE}/v1/proxy/npm"
        _ok "npm — registry → ${BASE}/v1/proxy/npm"
    fi
}

# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------

_pip_conf() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "$HOME/Library/Application Support/pip/pip.conf"
    else
        echo "${XDG_CONFIG_HOME:-$HOME/.config}/pip/pip.conf"
    fi
}

setup_pip() {
    if ! _has pip3 && ! _has pip; then _skip "pip — not installed"; return; fi
    local conf; conf="$(_pip_conf)"
    local url="${BASE}/v1/proxy/pypi/simple/"

    if $UNDO; then
        if [ -f "$conf" ] && grep -qF "$url" "$conf" 2>/dev/null; then
            local tmpf; tmpf=$(mktemp)
            grep -vF "index-url = $url" "$conf" > "$tmpf" && mv "$tmpf" "$conf"
            _ok "pip — index-url removed from $(basename "$conf")"
        else
            _skip "pip — not configured (nothing to undo)"
        fi
    else
        mkdir -p "$(dirname "$conf")"
        if [ -f "$conf" ] && grep -q "^index-url" "$conf" 2>/dev/null; then
            local tmpf; tmpf=$(mktemp)
            sed "s|^index-url.*|index-url = ${url}|" "$conf" > "$tmpf" && mv "$tmpf" "$conf"
        else
            if ! grep -q '^\[global\]' "$conf" 2>/dev/null; then
                printf '\n[global]\n' >> "$conf"
            fi
            printf 'index-url = %s\n' "$url" >> "$conf"
        fi
        _ok "pip — index-url → $url"
        _info "config: $conf"
    fi
}

# ---------------------------------------------------------------------------
# dotnet / NuGet
# ---------------------------------------------------------------------------

setup_nuget() {
    if ! _has dotnet; then _skip "dotnet/NuGet — not installed"; return; fi
    local src_name="package-warden"
    local src_url="${BASE}/v1/proxy/nuget/v3/index.json"

    if $UNDO; then
        if dotnet nuget list source 2>/dev/null | grep -qi "$src_name"; then
            dotnet nuget remove source "$src_name"
            dotnet nuget enable source "nuget.org"
            _ok "dotnet/NuGet — package-warden source removed, nuget.org re-enabled"
        else
            _skip "dotnet/NuGet — not configured (nothing to undo)"
        fi
    else
        dotnet nuget remove source "$src_name" 2>/dev/null || true
        dotnet nuget add source "$src_url" --name "$src_name" --allow-insecure-connections
        dotnet nuget disable source "nuget.org"
        _ok "dotnet/NuGet — source → $src_url"
        _info "(nuget.org disabled)"
    fi
}

# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

setup_cargo() {
    if ! _has cargo; then
        _skip "cargo — not installed"
        return
    fi
    local cargo_config="$HOME/.cargo/config.toml"
    local marker="cargo"
    local cargo_url="sparse+${BASE}/v1/proxy/cargo/"

    if $UNDO; then
        _strip_markers "$cargo_config" "$marker"
        if [ -f "$cargo_config" ] && [ ! -s "$cargo_config" ]; then
            rm -f "$cargo_config"
        fi
        _ok "cargo — config.toml restored"
    else
        mkdir -p "$HOME/.cargo"
        _strip_markers "$cargo_config" "$marker" 2>/dev/null || true
        {
            printf '\n# --- package-warden:%s start ---\n' "$marker"
            printf '[source.crates-io]\nreplace-with = "package-warden"\n\n'
            printf '[source.package-warden]\nregistry = "%s"\n' "$cargo_url"
            printf '# --- package-warden:%s end ---\n' "$marker"
        } >> "$cargo_config"
        _ok "cargo — registry → $cargo_url"
        _info "config: $cargo_config"
    fi
}

# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------

_shell_profile() {
    local shell_name; shell_name="$(basename "${SHELL:-bash}")"
    case "$shell_name" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash)
            if [[ "$OSTYPE" == "darwin"* ]]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.bashrc"
            fi
            ;;
        fish) echo "$HOME/.config/fish/config.fish" ;;
        *)    echo "$HOME/.profile" ;;
    esac
}

setup_go() {
    if ! _has go; then _skip "go — not installed"; return; fi
    local profile; profile="$(_shell_profile)"
    local marker="golang"
    local goproxy="${BASE}/v1/proxy/golang,direct"

    if $UNDO; then
        _strip_markers "$profile" "$marker"
        unset GOPROXY 2>/dev/null || true
        _ok "go — GOPROXY removed from $(basename "$profile")"
    else
        _strip_markers "$profile" "$marker" 2>/dev/null || true
        {
            printf '\n# --- package-warden:%s start ---\n' "$marker"
            printf 'export GOPROXY="%s"\n' "$goproxy"
            printf '# --- package-warden:%s end ---\n' "$marker"
        } >> "$profile"
        export GOPROXY="$goproxy"
        _ok "go — GOPROXY → $goproxy"
        _info "profile: $profile  (run: source $profile)"
    fi
}

# ---------------------------------------------------------------------------
# Bundler / RubyGems
# ---------------------------------------------------------------------------

setup_bundler() {
    if ! _has bundle; then _skip "bundler — not installed"; return; fi
    if $UNDO; then
        bundle config --delete "mirror.https://rubygems.org" 2>/dev/null || true
        _ok "bundler — mirror removed"
    else
        bundle config set "mirror.https://rubygems.org" "${BASE}/v1/proxy/gem"
        _ok "bundler — mirror → ${BASE}/v1/proxy/gem"
    fi
}

# ---------------------------------------------------------------------------
# Maven (instructions only — settings.xml is too project-specific to modify)
# ---------------------------------------------------------------------------

show_maven_instructions() {
    if ! _has mvn; then return; fi
    if $UNDO; then
        echo ""
        echo "  Maven: remove the following mirror from ~/.m2/settings.xml:"
    else
        echo ""
        echo "  Maven: add the following mirror to your ~/.m2/settings.xml:"
    fi
    cat <<EOF
    <mirrors>
      <mirror>
        <id>package-warden</id>
        <mirrorOf>central</mirrorOf>
        <url>${BASE}/v1/proxy/maven</url>
      </mirror>
    </mirrors>
EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if $UNDO; then
    echo "Removing Package Warden proxy settings from package managers..."
else
    echo "Configuring package managers to use Package Warden at ${BASE} ..."
fi
echo ""

setup_npm     || true
setup_pip     || true
setup_nuget   || true
setup_cargo   || true
setup_go      || true
setup_bundler || true

echo ""
echo "Done — configured: ${COUNT_OK}, skipped (not installed): ${COUNT_SKIP}"

show_maven_instructions

if ! $UNDO; then
    echo ""
    echo "Start Package Warden: ./package-warden.sh"
    echo "Dashboard:            ${BASE}/ui"
fi
