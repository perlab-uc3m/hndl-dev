#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/openssl3_local"
SRC_DIR="${INSTALL_DIR}/src"
OPENSSL_TAG="openssl-3.6.0"
JOBS="$(nproc)"
DO_CLONE=0
DO_BUILD=0
DO_INSTALL=0
VERBOSE=0
PATCH_FILE=""

# Resolve script and repo roots to locate default patch file reliably
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(readlink -f "${SCRIPT_DIR}/..")"
DEFAULT_PATCH="${REPO_ROOT}/patches/openssl-3.6.0-tls13-debug.patch"

usage() {
  cat <<EOF
Usage: $0 [options]
Options:
  -p <dir>   Install directory (default: $INSTALL_DIR)
  -v <tag>   OpenSSL tag/branch to checkout (default: $OPENSSL_TAG)
  -j <n>     Make jobs (default: $JOBS)
  -c         Clone the OpenSSL repository (only)
  -P <file>  Apply specific patch file to the cloned source (default: $DEFAULT_PATCH)
  -b         Build OpenSSL from source (configure/make)
  -i         Install built OpenSSL to prefix (only with build)
  -g         Print grep hints to find the ephemeral key generation site
  -V         Verbose
  -h         Show this help
EOF
  exit 1
}

while getopts "p:v:j:cP:bigVh" opt; do
  case "$opt" in
    p) INSTALL_DIR="$OPTARG" ;;
    v) OPENSSL_TAG="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    c) DO_CLONE=1 ;;
    P) PATCH_FILE="$OPTARG" ;;
    b) DO_BUILD=1 ;;
    i) DO_INSTALL=1 ;;
    V) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

INSTALL_DIR="$(readlink -f "$INSTALL_DIR")"
SRC_DIR="${INSTALL_DIR}/src"
LOCAL_PREFIX="${INSTALL_DIR}/.local"
if [ -z "${PATCH_FILE}" ]; then
  PATCH_FILE="${DEFAULT_PATCH}"
fi
# If the patch file exists, canonicalize to absolute path for safety
if [ -f "${PATCH_FILE}" ]; then
  PATCH_FILE="$(readlink -f "${PATCH_FILE}")"
fi

mkdir -p "$INSTALL_DIR"
mkdir -p "$SRC_DIR"
mkdir -p "$LOCAL_PREFIX"

echov() { if [ "${VERBOSE:-0}" -eq 1 ]; then echo "$@"; fi }

clone_repo() {
  if [ -d "$SRC_DIR/openssl/.git" ]; then
    echo "OpenSSL source already present at $SRC_DIR/openssl"
    # Even if already present, try to apply patch if provided
    if [ -f "$PATCH_FILE" ]; then
      echo "Attempting to apply patch to existing source: $PATCH_FILE"
      if git -C "$SRC_DIR/openssl" apply --check "$PATCH_FILE"; then
        git -C "$SRC_DIR/openssl" apply "$PATCH_FILE" && echo "Patch applied successfully to existing source."
      else
        echo "Patch could not be cleanly applied (it may already be applied or conflicts with current source)."
      fi
    else
      echo "No patch applied (patch file not found at $PATCH_FILE)."
    fi
    return 0
  fi
  echo "Cloning OpenSSL tag '$OPENSSL_TAG' into $SRC_DIR ..."
  git clone --branch "$OPENSSL_TAG" --depth 1 https://github.com/openssl/openssl.git "$SRC_DIR/openssl"
  echo "Clone complete."
  if [ -f "$PATCH_FILE" ]; then
    echo "Found patch file: $PATCH_FILE"
    echo "Checking patch applicability..."
    git -C "$SRC_DIR/openssl" apply --check "$PATCH_FILE" || { echo "Patch check failed; aborting."; exit 1; }
    git -C "$SRC_DIR/openssl" apply "$PATCH_FILE" || { echo "Patch application failed; aborting."; exit 1; }
    echo "Patch applied successfully."
  else
    echo "No patch applied (patch file not found at $PATCH_FILE)."
  fi
}

build_openssl() {
  if [ ! -d "$SRC_DIR/openssl" ]; then
    echo "OpenSSL source not found at $SRC_DIR/openssl. Run with -c to clone first."
    exit 1
  fi
  pushd "$SRC_DIR/openssl" > /dev/null
  echov "Configuring OpenSSL (prefix=$LOCAL_PREFIX)"
  ./Configure --prefix="$LOCAL_PREFIX" no-shared CFLAGS="-DDEMO_PRINT_EPHEMERAL=1"
  echov "Running make -j${JOBS}"
  make -j"${JOBS}"
  if [ "${DO_INSTALL}" -eq 1 ]; then
    make install_sw
    echo "Installed. Consider adding LD_LIBRARY_PATH=\"$LOCAL_PREFIX/lib:\$LD_LIBRARY_PATH\""
  else
    echo "Build complete (not installed)."
  fi
  popd > /dev/null
}

if [ "${DO_CLONE}" -eq 1 ]; then
  clone_repo
fi

if [ "${DO_BUILD}" -eq 1 ]; then
  build_openssl
fi

echo "Done."
exit 0
