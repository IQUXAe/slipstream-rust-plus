#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
PROFILE="${PROFILE:-release}"
VERSION="${VERSION:-}"

usage() {
  cat <<'EOF'
Usage: ./scripts/package_release.sh [--target <triple>] [--version <tag>] [--profile <name>]

Builds slipstream-client and slipstream-server, then packages them into dist/.

Options:
  --target <triple>   Optional Rust target triple, e.g. x86_64-unknown-linux-gnu
  --version <tag>     Optional version label used in the archive name
  --profile <name>    Cargo profile to build, default: release
  -h, --help          Show this help

Environment:
  TARGET_TRIPLE       Same as --target
  VERSION             Same as --version
  PROFILE             Same as --profile
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_TRIPLE="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${PROFILE}" ]]; then
  echo "PROFILE must not be empty" >&2
  exit 2
fi

build_args=("-p" "slipstream-client" "-p" "slipstream-server")
if [[ "${PROFILE}" == "release" ]]; then
  build_args+=("--release")
else
  build_args+=("--profile" "${PROFILE}")
fi
if [[ -n "${TARGET_TRIPLE}" ]]; then
  build_args+=("--target" "${TARGET_TRIPLE}")
fi

echo "Building binaries with: cargo build ${build_args[*]}"
(cd "${ROOT_DIR}" && cargo build "${build_args[@]}")

if [[ -n "${TARGET_TRIPLE}" ]]; then
  BIN_DIR="${ROOT_DIR}/target/${TARGET_TRIPLE}/${PROFILE}"
  target_label="${TARGET_TRIPLE}"
else
  BIN_DIR="${ROOT_DIR}/target/${PROFILE}"
  target_label="$(rustc -vV | sed -n 's/^host: //p')"
fi

if [[ ! -x "${BIN_DIR}/slipstream-client" || ! -x "${BIN_DIR}/slipstream-server" ]]; then
  echo "Expected binaries not found in ${BIN_DIR}" >&2
  exit 1
fi

archive_version="${VERSION}"
if [[ -z "${archive_version}" ]]; then
  archive_version="$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || true)"
fi
if [[ -z "${archive_version}" ]]; then
  archive_version="dev"
fi

base_name="slipstream-${archive_version}-${target_label}"
package_dir="${DIST_DIR}/${base_name}"
archive_path="${DIST_DIR}/${base_name}.tar.gz"

rm -rf "${package_dir}"
mkdir -p "${package_dir}"

cp "${BIN_DIR}/slipstream-client" "${package_dir}/"
cp "${BIN_DIR}/slipstream-server" "${package_dir}/"
cat > "${package_dir}/README.txt" <<EOF
Slipstream release package

Contents:
- slipstream-client
- slipstream-server

Quick start:
1. Run slipstream-server on the remote host.
2. Copy the server certificate PEM to the client host.
3. Run slipstream-client with --cert pointing to that PEM file.

See docs/usage.md for detailed flags and examples.
EOF

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${package_dir}"
    sha256sum slipstream-client slipstream-server README.txt > SHA256SUMS
  )
else
  (
    cd "${package_dir}"
    shasum -a 256 slipstream-client slipstream-server README.txt > SHA256SUMS
  )
fi

rm -f "${archive_path}"
tar -C "${DIST_DIR}" -czf "${archive_path}" "${base_name}"

echo "Packaged release directory: ${package_dir}"
echo "Packaged release archive:   ${archive_path}"
