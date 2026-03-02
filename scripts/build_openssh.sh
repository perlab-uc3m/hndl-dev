   #!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# build_openssh.sh - Download, patch, and build OpenSSH with key logging
# ============================================================================
#
# Analogous to build_openssl.sh but for OpenSSH.
# Used to capture SSH ephemeral key exchange secrets for traffic decryption.
#
# SSH Key Exchange (KEX) differs from TLS:
#   - Uses Curve25519/ECDH/DH for key agreement
#   - Derives session keys via RFC 4253 formulas (not HKDF labels)
#   - Key files to patch: kex.c, kexc25519.c, kexecdh.c, kexdh.c
#
# ============================================================================

INSTALL_DIR="./openssh"
SRC_DIR=""
OPENSSH_VERSION="9.9p2"
JOBS="$(nproc)"
DO_DOWNLOAD=0
DO_BUILD=0
DO_INSTALL=0
DO_EXPLORE=0
VERBOSE=0
PATCH_FILE=""
SKIP_PATCH=0

# Resolve script and repo roots to locate default patch file reliably
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(readlink -f "${SCRIPT_DIR}/..")"
DEFAULT_PATCH="${REPO_ROOT}/patches/openssh-${OPENSSH_VERSION}-keylog.patch"

usage() {
  cat <<EOF
Usage: $0 [options]
Options:
  -p <dir>   Install directory (default: $INSTALL_DIR)
  -v <ver>   OpenSSH version to download (default: $OPENSSH_VERSION)
  -j <n>     Make jobs (default: $JOBS)
  -c         Download and extract OpenSSH source
  -P <file>  Apply specific patch file (default: $DEFAULT_PATCH if exists and non-empty)
  -S         Skip patch application (useful for exploration)
  -b         Build OpenSSH from source (autoreconf/configure/make)
  -i         Install built OpenSSH to prefix
  -e         Explore: print key exchange code locations for patching
  -V         Verbose
  -h         Show this help

Examples:
  # Download source and explore KEX code locations
  $0 -c -e

  # Download without patching, then explore
  $0 -c -S -e

  # Build with patch
  $0 -c -b -i

  # Just explore existing source
  $0 -p ./openssh -e
EOF
  exit 1
}

while getopts "p:v:j:cP:SbieVh" opt; do
  case "$opt" in
    p) INSTALL_DIR="$OPTARG" ;;
    v) OPENSSH_VERSION="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    c) DO_DOWNLOAD=1 ;;
    P) PATCH_FILE="$OPTARG" ;;
    S) SKIP_PATCH=1 ;;
    b) DO_BUILD=1 ;;
    i) DO_INSTALL=1 ;;
    e) DO_EXPLORE=1 ;;
    V) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

# Normalize paths
mkdir -p "$INSTALL_DIR"
INSTALL_DIR="$(readlink -f "$INSTALL_DIR")"
# Convert version like "9.9p2" to path format "V_9_9_P2"
VERSION_TAG="V_${OPENSSH_VERSION//./_}"
VERSION_TAG="${VERSION_TAG//p/_P}"
SRC_DIR="${INSTALL_DIR}/src/openssh-portable-${VERSION_TAG}"
LOCAL_PREFIX="${INSTALL_DIR}/.local"

if [ -z "${PATCH_FILE}" ]; then
  PATCH_FILE="${DEFAULT_PATCH}"
fi
# Canonicalize patch path if it exists
if [ -f "${PATCH_FILE}" ]; then
  PATCH_FILE="$(readlink -f "${PATCH_FILE}")"
fi

echov() { if [ "${VERBOSE:-0}" -eq 1 ]; then echo "$@"; fi }

# Check for required build dependencies
check_deps() {
  local missing=()
  for cmd in gcc make autoconf automake git; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "WARNING: Missing dependencies: ${missing[*]}"
    echo "Install with: sudo apt install build-essential autoconf automake git zlib1g-dev libssl-dev libpam0g-dev"
  fi
}

download_source() {
  # Convert version like "9.9p2" to tag format "V_9_9_P2"
  local version_underscored="${OPENSSH_VERSION//./_}"
  local git_tag="V_${version_underscored//p/_P}"
  
  mkdir -p "${INSTALL_DIR}/src"
  
  if [ -d "$SRC_DIR/.git" ]; then
    echo "OpenSSH source already present at $SRC_DIR"
  else
    echo "Cloning OpenSSH portable tag '$git_tag' into ${INSTALL_DIR}/src ..."
    git clone --branch "$git_tag" --depth 1 \
      https://github.com/openssh/openssh-portable.git \
      "$SRC_DIR"
    echo "Clone complete."
  fi
  
  # Apply patch if exists and non-empty, unless skipped
  if [ "${SKIP_PATCH}" -eq 1 ]; then
    echo "Skipping patch application (-S flag)."
    return 0
  fi
  
  if [ -f "$PATCH_FILE" ] && [ -s "$PATCH_FILE" ]; then
    echo "Found patch file: $PATCH_FILE"
    echo "Checking patch applicability..."
    if git -C "$SRC_DIR" apply --check "$PATCH_FILE" 2>/dev/null; then
      git -C "$SRC_DIR" apply "$PATCH_FILE"
      echo "Patch applied successfully."
    else
      echo "Patch could not be cleanly applied (may already be applied or conflicts)."
    fi
  else
    echo "No patch applied (patch file not found or empty at $PATCH_FILE)."
    echo "Run with -e to explore source and create a patch."
  fi
}

build_openssh() {
  if [ ! -d "$SRC_DIR" ]; then
    echo "OpenSSH source not found at $SRC_DIR. Run with -c to download first."
    exit 1
  fi
  
  check_deps
  
  pushd "$SRC_DIR" > /dev/null
  
  # Run autoreconf if configure doesn't exist or is outdated
  # OpenSSH from git requires autoreconf; configure.ac may be newer than configure
  if [ ! -f "configure" ] || [ "configure.ac" -nt "configure" ]; then
    echov "Running autoreconf (configure missing or outdated)..."
    autoreconf -fvi
  fi
  
  echov "Configuring OpenSSH (prefix=$LOCAL_PREFIX)"
  ./configure --prefix="$LOCAL_PREFIX" \
    --with-privsep-path="${LOCAL_PREFIX}/var/empty" \
    --with-pid-dir="${LOCAL_PREFIX}/var/run" \
    CFLAGS="-DSSH_KEYLOG_DEBUG=1 -g -O2"
  
  echov "Running make -j${JOBS}"
  make -j"${JOBS}"
  
  if [ "${DO_INSTALL}" -eq 1 ]; then
    mkdir -p "${LOCAL_PREFIX}/var/empty"
    mkdir -p "${LOCAL_PREFIX}/var/run"
    make install
    echo "Installed to $LOCAL_PREFIX"
    echo "Binaries: $LOCAL_PREFIX/bin/ssh, $LOCAL_PREFIX/sbin/sshd"
  else
    echo "Build complete (not installed). Binaries in $SRC_DIR"
  fi
  
  popd > /dev/null
}

explore_kex_code() {
  if [ ! -d "$SRC_DIR" ]; then
    echo "OpenSSH source not found at $SRC_DIR. Run with -c to download first."
    exit 1
  fi
  
  echo "============================================================================"
  echo "OpenSSH Key Exchange (KEX) Code Exploration"
  echo "Source directory: $SRC_DIR"
  echo "============================================================================"
  echo ""
  
  echo "=== KEY FILES FOR PATCHING ==="
  echo ""
  echo "1. kex.c - Core key exchange logic and key derivation"
  echo "2. kexc25519.c - Curve25519 key exchange (modern default)"
  echo "3. kexecdh.c - ECDH key exchange (NIST curves)"
  echo "4. kexdh.c - Classical Diffie-Hellman"
  echo "5. kexgen.c - Generic KEX framework"
  echo "6. kex.h - Data structures (struct kex, struct sshkey)"
  echo ""
  
  echo "=== SEARCHING FOR KEY GENERATION SITES ==="
  echo ""
  
  # Find where ephemeral keys are generated
  echo "--- Curve25519 ephemeral key generation (kexc25519.c) ---"
  if [ -f "$SRC_DIR/kexc25519.c" ]; then
    grep -n "crypto_scalarmult\|kexc25519_keygen\|curve25519" "$SRC_DIR/kexc25519.c" | head -20 || true
  fi
  echo ""
  
  echo "--- ECDH key generation (kexecdh.c) ---"
  if [ -f "$SRC_DIR/kexecdh.c" ]; then
    grep -n "EC_KEY_generate\|kex_ecdh_keypair\|EC_POINT" "$SRC_DIR/kexecdh.c" | head -20 || true
  fi
  echo ""
  
  echo "--- Key derivation (kex.c) ---"
  if [ -f "$SRC_DIR/kex.c" ]; then
    grep -n "derive_keys\|kex_derive_keys\|NEWKEYS\|session_id" "$SRC_DIR/kex.c" | head -30 || true
  fi
  echo ""
  
  echo "--- Shared secret computation ---"
  grep -rn "shared_secret\|kex->.*secret\|K =" "$SRC_DIR"/*.c 2>/dev/null | head -20 || true
  echo ""
  
  echo "=== KEY DATA STRUCTURES (kex.h) ==="
  if [ -f "$SRC_DIR/kex.h" ]; then
    echo "--- struct kex definition ---"
    grep -n -A 50 "^struct kex {" "$SRC_DIR/kex.h" | head -60 || true
  fi
  echo ""
  
  echo "=== FILES TO EXAMINE ==="
  echo ""
  ls -la "$SRC_DIR"/kex*.c "$SRC_DIR"/kex*.h 2>/dev/null || true
  echo ""
  
  echo "=== RECOMMENDED PATCH POINTS ==="
  echo ""
  cat <<'PATCH_GUIDE'
To create an SSH keylog patch similar to the OpenSSL TLS 1.3 patch:

1. **kexc25519.c** - After kexc25519_keygen() generates keypair:
   - Print: SSH_KEYLOG_CLIENT_EPHEMERAL_PRIV, SSH_KEYLOG_CLIENT_EPHEMERAL_PUB
   - Print: SSH_KEYLOG_SERVER_EPHEMERAL_PUB (received from peer)

2. **kex.c** - In kex_derive_keys() after computing shared secret K:
   - Print: SSH_KEYLOG_SHARED_SECRET_K
   - Print: SSH_KEYLOG_EXCHANGE_HASH_H
   - Print: SSH_KEYLOG_SESSION_ID
   - Print: SSH_KEYLOG_DERIVED_KEY_* (for each direction/purpose)

3. **Key derivation formula (RFC 4253)**:
   K = shared secret (ECDH result)
   H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
   session_id = first H
   
   Encryption keys:
   - IV client->server:  hash(K || H || "A" || session_id)
   - IV server->client:  hash(K || H || "B" || session_id)
   - Key client->server: hash(K || H || "C" || session_id)
   - Key server->client: hash(K || H || "D" || session_id)
   - MAC client->server: hash(K || H || "E" || session_id)
   - MAC server->client: hash(K || H || "F" || session_id)

4. **Output format** (similar to OpenSSL patch):
   fprintf(stderr, "SSH_KEYLOG_SHARED_SECRET_K= ");
   for (i = 0; i < sshbuf_len(shared_secret); i++)
       fprintf(stderr, "%02x", sshbuf_ptr(shared_secret)[i]);
   fprintf(stderr, "\n");

5. **Compile flag**: -DSSH_KEYLOG_DEBUG=1
PATCH_GUIDE

  echo ""
  echo "=== NEXT STEPS ==="
  echo "1. Examine the files listed above"
  echo "2. Add debug prints at the recommended patch points"
  echo "3. Generate patch: cd $SRC_DIR && git diff > patch.diff"
  echo "4. Move patch to: ${REPO_ROOT}/patches/openssh-${OPENSSH_VERSION}-keylog.patch"
  echo ""
}

# Main execution
if [ "${DO_DOWNLOAD}" -eq 1 ]; then
  download_source
fi

if [ "${DO_EXPLORE}" -eq 1 ]; then
  explore_kex_code
fi

if [ "${DO_BUILD}" -eq 1 ]; then
  build_openssh
fi

if [ "${DO_DOWNLOAD}" -eq 0 ] && [ "${DO_BUILD}" -eq 0 ] && [ "${DO_EXPLORE}" -eq 0 ]; then
  echo "No action specified. Use -c to download, -e to explore, -b to build."
  echo "Run '$0 -h' for help."
fi

echo "Done."
exit 0