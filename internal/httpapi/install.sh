#!/usr/bin/env bash
set -euo pipefail

REPO="manovaspace/orbit-cli"
INSTALL_DIR="${HOME}/.local/bin"

if [ -z "${ORBIT_VERSION:-}" ]; then
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/${REPO}/releases/latest 2>/dev/null | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4 || true)"
  if [ -n "$LATEST_TAG" ]; then
    VERSION="$LATEST_TAG"
  else
    VERSION="v0.5.0"
  fi
else
  VERSION="$ORBIT_VERSION"
fi

# Host constraints
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
  echo "Error: Orbit requires Linux (Ubuntu 24.04 or 26.04 LTS, amd64)" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ;;
  *)
    echo "Error: Unsupported architecture '$ARCH' (amd64 required)" >&2
    exit 1
    ;;
esac

OS_ID=""
OS_VERSION_ID=""
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
elif [ -f /usr/lib/os-release ]; then
  # shellcheck disable=SC1091
  . /usr/lib/os-release
  OS_ID="${ID:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
fi

if [ "$OS_ID" != "ubuntu" ]; then
  echo "Error: Orbit requires Linux (Ubuntu 24.04 or 26.04 LTS, amd64)" >&2
  exit 1
fi

case "$OS_VERSION_ID" in
  24.04*|26.04*) ;;
  *)
    echo "Error: Orbit requires Linux (Ubuntu 24.04 or 26.04 LTS, amd64)" >&2
    exit 1
    ;;
esac

if [ -f /proc/version ]; then
  PROC_VERSION="$(cat /proc/version)"
  if echo "$PROC_VERSION" | grep -qi microsoft; then
    IS_WSL2=false
    if echo "$PROC_VERSION" | grep -qi wsl2; then
      IS_WSL2=true
    fi
    if [ -e /run/WSL ]; then
      IS_WSL2=true
    fi
    if [ "$IS_WSL2" = false ]; then
      echo "Error: WSL1 is not supported (WSL2 required)" >&2
      exit 1
    fi
  fi
fi

LOGIN_SHELL="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7 || true)"
SHELL_BASE="$(basename "${LOGIN_SHELL:-}")"
if [ "$SHELL_BASE" != "zsh" ]; then
  echo "Error: Orbit requires zsh as your login shell." >&2
  echo "  sudo apt install zsh" >&2
  echo "  chsh -s \$(command -v zsh)" >&2
  exit 1
fi

# Download helper
download() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    echo "Error: curl or wget is required to install Orbit" >&2
    exit 1
  fi
}

# Process flags
YES_FLAG=false
for arg in "$@"; do
  if [ "$arg" = "-y" ] || [ "$arg" = "--yes" ]; then
    YES_FLAG=true
  fi
done

# Colors
BOLD="\033[1m"
BLUE="\033[34m"
CYAN="\033[36m"
GREEN="\033[32m"
GRAY="\033[90m"
RESET="\033[0m"

if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
  BOLD=""
  BLUE=""
  CYAN=""
  GREEN=""
  GRAY=""
  RESET=""
fi

echo -e "\n${BOLD}${BLUE}Orbit Platform CLI Installer${RESET}\n"
echo -e "  ${BOLD}Version:${RESET}      ${CYAN}${VERSION}${RESET}"
echo -e "  ${BOLD}Platform:${RESET}     linux / amd64"
echo -e "  ${BOLD}Destination:${RESET}  ${INSTALL_DIR}/orbit"
echo -e "  ${BOLD}Shortcuts:${RESET}    ${INSTALL_DIR}/o ${GRAY}(binary symlink)${RESET}\n"

# Prompt confirmation helper reading strictly from /dev/tty
prompt_confirm() {
  local prompt_msg="$1"

  if [ "$YES_FLAG" = true ] || [ "${ORBIT_YES:-}" = "1" ]; then
    return 0
  fi

  if ! (exec 2>/dev/null 3</dev/tty); then
    echo "Error: Non-interactive environment detected without -y / --yes flag. Use -y or --yes to proceed non-interactively." >&2
    exit 1
  fi

  echo -ne "$prompt_msg"
  local response=""
  if read -r response </dev/tty; then
    case "$response" in
      [yY]|[yY][eE][sS])
        return 0
        ;;
      *)
        return 1
        ;;
    esac
  fi
  return 1
}

# Interactive confirmation prompt
if [ "$YES_FLAG" = false ] && [ "${ORBIT_YES:-}" != "1" ]; then
  if ! prompt_confirm "  ${BOLD}Do you want to proceed with the installation?${RESET} (y/N) [n]: "; then
    echo -e "\n  ${GRAY}Installation cancelled. No changes were made to your system.${RESET}\n"
    exit 0
  fi
  echo ""
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

ORBIT_BIN="orbit-linux-amd64"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Download binaries
echo -e "  ${GRAY}↓ Downloading release binaries from GitHub...${RESET}"
download "${BASE_URL}/${ORBIT_BIN}" "${TMP_DIR}/orbit"
chmod +x "${TMP_DIR}/orbit"

# Install binaries
mkdir -p "$INSTALL_DIR"
cp "${TMP_DIR}/orbit" "${INSTALL_DIR}/orbit"
chmod 755 "${INSTALL_DIR}/orbit"

# Create shortcut symlinks (o -> orbit)
ln -sf "orbit" "${INSTALL_DIR}/o" 2>/dev/null || true

# Clean up any legacy shell profile alias configuration from previous versions
CLEAN_PROFILES=(
  "${HOME}/.bashrc"
  "${HOME}/.bash_profile"
  "${HOME}/.zshrc"
  "${HOME}/.profile"
  "${HOME}/.config/fish/config.fish"
)

for rc in "${CLEAN_PROFILES[@]}"; do
  if [ -f "$rc" ] && [ -w "$rc" ]; then
    if grep -q -E "(# Orbit CLI shortcut|alias o=[\"']?orbit[\"']?)" "$rc" 2>/dev/null; then
      tmp_rc="$(mktemp)"
      grep -v -E "(# Orbit CLI shortcut|alias o=[\"']?orbit[\"']?)" "$rc" > "$tmp_rc" || true
      cat "$tmp_rc" > "$rc"
      rm -f "$tmp_rc"
    fi
  fi
done

# Direct execution if non-flag arguments passed
NON_FLAG_ARGS=()
for arg in "$@"; do
  if [ "$arg" != "-y" ] && [ "$arg" != "--yes" ]; then
    NON_FLAG_ARGS+=("$arg")
  fi
done

if [ ${#NON_FLAG_ARGS[@]} -gt 0 ]; then
  exec "${INSTALL_DIR}/orbit" "${NON_FLAG_ARGS[@]}"
fi

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "Error: ~/.local/bin is not on PATH (add export PATH=\"\$HOME/.local/bin:\$PATH\" to ~/.zshrc)" >&2
    exit 1
    ;;
esac

echo -e "  ${GREEN}✔${RESET} ${BOLD}Orbit ${VERSION} installed successfully!${RESET}\n"
echo -e "  ${BOLD}Installed to:${RESET}  ${INSTALL_DIR}/orbit"
echo -e "  ${BOLD}Commands:${RESET}      ${CYAN}orbit${RESET}, ${CYAN}o${RESET}\n"

echo -e "  ${BOLD}Get started:${RESET}"
echo -e "    ${CYAN}o admin init${RESET}  ${GRAY}# Platform owner (this machine vault)${RESET}"
echo -e "    ${CYAN}o invite create <email>${RESET}  ${GRAY}# Signed onboarding token${RESET}"
echo -e "    ${CYAN}o staff create --uid … --forward …${RESET}  ${GRAY}# Directory (needs orbit-staff)${RESET}"
echo -e "    ${CYAN}o onboard${RESET}     ${GRAY}# Invitee wizard (token from orbit invite)${RESET}"
echo -e "    ${CYAN}o doctor${RESET}      ${GRAY}# Verify system prerequisites${RESET}"
echo -e "    ${CYAN}o version${RESET}     ${GRAY}# Check installed version${RESET}\n"
