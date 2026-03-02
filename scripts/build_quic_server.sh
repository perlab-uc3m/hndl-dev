#!/usr/bin/env bash
# Build the QUIC server demo from the upstream OpenSSL source, applying
# our minimal HN-DL patch (keylog, one-shot, configurable response).
#
# The patch is applied to a temporary copy; the OpenSSL tree stays clean.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(readlink -f "${SCRIPT_DIR}/..")"
OPENSSL_LOCAL="${REPO_ROOT}/openssl/.local"
OPENSSL_SRC="${REPO_ROOT}/openssl/src/openssl"
PATCH="${REPO_ROOT}/patches/openssl-3.6.0-quic-server.patch"
OUT="${OPENSSL_LOCAL}/bin/quic_server"

# Work in a temp directory so the upstream tree is never modified
BUILD_DIR=$(mktemp -d)
trap "rm -rf '${BUILD_DIR}'" EXIT

# Copy the upstream demo source
mkdir -p "${BUILD_DIR}/demos/quic/server"
cp "${OPENSSL_SRC}/demos/quic/server/server.c" \
   "${BUILD_DIR}/demos/quic/server/server.c"

# Apply the HN-DL patch
echo "Applying patch: $(basename "${PATCH}")"
(cd "${BUILD_DIR}" && patch -p1 < "${PATCH}")

SRC="${BUILD_DIR}/demos/quic/server/server.c"

echo "Building QUIC server..."
echo "  OpenSSL: ${OPENSSL_LOCAL}"
echo "  Source:  ${SRC} (patched copy)"
echo "  Output:  ${OUT}"

cc -Wall -O2 \
    -I"${OPENSSL_LOCAL}/include" \
    -o "${OUT}" "${SRC}" \
    -L"${OPENSSL_LOCAL}/lib64" -lssl -lcrypto \
    -lpthread -ldl

chmod +x "${OUT}"
echo "Built: ${OUT}"
"${OUT}" -h 2>&1 || true
echo "Done."
