#!/usr/bin/env bash
set -euo pipefail

REPO="manovaspace/orbit-cli"
INSTALL_DIR="${ORBIT_INSTALL_DIR:-/usr/local/bin}"

if [ -z "${ORBIT_VERSION:-}" ]; then
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/${REPO}/releases/latest 2>/dev/null | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4 || true)"
  if [ -n "$LATEST_TAG" ]; then
    VERSION="$LATEST_TAG"
  else
    VERSION="v0.4.5"
  fi
else
  VERSION="$ORBIT_VERSION"
fi

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)   OS="linux" ;;
  Darwin*)  OS="darwin" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *)
    echo "Error: Unsupported operating system '$OS'" >&2
    exit 1
    ;;
esac

EXT=""
if [ "$OS" = "windows" ]; then
  EXT=".exe"
fi

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Error: Unsupported architecture '$ARCH'" >&2
    exit 1
    ;;
esac

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

# Determine write permission for destination directory
check_write_permission() {
  local dir="$1"
  while [ ! -d "$dir" ]; do
    dir="$(dirname "$dir")"
    if [ "$dir" = "/" ] || [ "$dir" = "." ]; then
      break
    fi
  done
  [ -w "$dir" ]
}

USE_SUDO=false
if [ "$(id -u)" -ne 0 ]; then
  if ! check_write_permission "$INSTALL_DIR"; then
    if command -v sudo >/dev/null 2>&1; then
      USE_SUDO=true
    else
      INSTALL_DIR="${HOME}/.local/bin"
    fi
  fi
fi

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
echo -e "  ${BOLD}Platform:${RESET}     ${OS} / ${ARCH}"
echo -e "  ${BOLD}Destination:${RESET}  ${INSTALL_DIR}/orbit${EXT}"
echo -e "  ${BOLD}Shortcuts:${RESET}    ${INSTALL_DIR}/o${EXT} ${GRAY}(binary symlink)${RESET}\n"

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

ORBIT_BIN="orbit-${OS}-${ARCH}${EXT}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Download binaries
echo -e "  ${GRAY}↓ Downloading release binaries from GitHub...${RESET}"
download "${BASE_URL}/${ORBIT_BIN}" "${TMP_DIR}/orbit${EXT}"
chmod +x "${TMP_DIR}/orbit${EXT}"

# Install binaries
if [ "$USE_SUDO" = true ]; then
  sudo mkdir -p "$INSTALL_DIR"
  sudo cp "${TMP_DIR}/orbit${EXT}" "${INSTALL_DIR}/orbit${EXT}"
  sudo chmod 755 "${INSTALL_DIR}/orbit${EXT}"
else
  mkdir -p "$INSTALL_DIR"
  cp "${TMP_DIR}/orbit${EXT}" "${INSTALL_DIR}/orbit${EXT}"
  chmod 755 "${INSTALL_DIR}/orbit${EXT}"
fi

# Create shortcut symlinks (o -> orbit)
if [ "$USE_SUDO" = true ]; then
  sudo ln -sf "orbit${EXT}" "${INSTALL_DIR}/o${EXT}" 2>/dev/null || true
else
  ln -sf "orbit${EXT}" "${INSTALL_DIR}/o${EXT}" 2>/dev/null || true
fi

# Direct execution if non-flag arguments passed
NON_FLAG_ARGS=()
for arg in "$@"; do
  if [ "$arg" != "-y" ] && [ "$arg" != "--yes" ]; then
    NON_FLAG_ARGS+=("$arg")
  fi
done

if [ ${#NON_FLAG_ARGS[@]} -gt 0 ]; then
  exec "${INSTALL_DIR}/orbit${EXT}" "${NON_FLAG_ARGS[@]}"
fi

echo -e "  ${GREEN}✔${RESET} ${BOLD}Orbit ${VERSION} installed successfully!${RESET}\n"
echo -e "  ${BOLD}Installed to:${RESET}  ${INSTALL_DIR}/orbit${EXT}"
echo -e "  ${BOLD}Commands:${RESET}      ${CYAN}orbit${RESET}, ${CYAN}o${RESET}\n"

echo -e "  ${BOLD}Get started:${RESET}"
echo -e "    ${CYAN}o admin init${RESET}  ${GRAY}# Platform owner (this machine vault)${RESET}"
echo -e "    ${CYAN}o onboard${RESET}     ${GRAY}# Invitee wizard (token from orbit invite)${RESET}"
echo -e "    ${CYAN}o doctor${RESET}      ${GRAY}# Verify system prerequisites${RESET}"
echo -e "    ${CYAN}o version${RESET}     ${GRAY}# Check installed version${RESET}\n"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "  Note: Add $INSTALL_DIR to your PATH to run 'orbit':"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    ;;
esac
