#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="wasm32-unknown-unknown"
WASM_BINDGEN_VERSION="0.2.70"
WASM_BINDGEN_SHA256="8864aed9fd5ca3d14ad368c399e3a0d28c4e5e7a70ed7ac54ce77997bc7cde71"
ARCHIVE_NAME="wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz"
ARCHIVE_URL="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/${ARCHIVE_NAME}"
BUILD_DIR="${ROOT_DIR}/target/worker-build"
TOOL_DIR="${BUILD_DIR}/wasm-bindgen-${WASM_BINDGEN_VERSION}"
PKG_DIR="${ROOT_DIR}/worker/pkg"

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required to verify the wasm-bindgen download" >&2
  exit 1
fi

rustup target add "${TARGET}"
mkdir -p "${BUILD_DIR}" "${PKG_DIR}"

archive="${BUILD_DIR}/${ARCHIVE_NAME}"
if [[ ! -x "${TOOL_DIR}/wasm-bindgen" ]]; then
  curl --fail --silent --show-error --location "${ARCHIVE_URL}" --output "${archive}"
  actual_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
  if [[ "${actual_sha256}" != "${WASM_BINDGEN_SHA256}" ]]; then
    echo "wasm-bindgen archive checksum mismatch" >&2
    exit 1
  fi
  rm -rf "${TOOL_DIR}"
  tar --extract --gzip --file "${archive}" --directory "${BUILD_DIR}"
  mv "${BUILD_DIR}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl" "${TOOL_DIR}"
fi

cargo build --release --target "${TARGET}"
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}"
"${TOOL_DIR}/wasm-bindgen" \
  --target bundler \
  --out-dir "${PKG_DIR}" \
  "${ROOT_DIR}/target/${TARGET}/release/sortasecret.wasm"

sed -i '1c\
let wasm;\
\
export function __wbg_set_wasm(value) { wasm = value; }\
' "${PKG_DIR}/sortasecret_bg.js"
cp "${ROOT_DIR}/worker/wasm-bootstrap.js" "${PKG_DIR}/sortasecret.js"
