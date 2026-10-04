#!/bin/sh
set -eu

cargo_version="$(
  awk -F '"' '/^rust-version = "/ { print $2 }' Cargo.toml
)"
toolchain_version="$(
  awk -F '"' '/^channel = "/ { print $2 }' rust-toolchain.toml
)"
docker_version="$(
  sed -nE \
    's/^FROM rust:([0-9]+\.[0-9]+\.[0-9]+)-alpine@sha256:.*/\1/p' \
    Dockerfile
)"
readme_version="$(
  sed -nE 's/.*MSRV-([0-9]+\.[0-9]+\.[0-9]+)-blue.*/\1/p' README.md
)"
contributing_version="$(
  sed -nE \
    's/.*MSRV: ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' \
    CONTRIBUTING.md
)"

if ! printf '%s\n' "${cargo_version}" \
  | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "Cargo.toml must contain exactly one X.Y.Z rust-version" >&2
  exit 1
fi

for entry in \
  "rust-toolchain.toml:${toolchain_version}" \
  "Dockerfile:${docker_version}" \
  "README.md:${readme_version}" \
  "CONTRIBUTING.md:${contributing_version}"; do
  file="${entry%%:*}"
  version="${entry#*:}"
  if [ "${version}" != "${cargo_version}" ]; then
    echo \
      "${file} Rust version '${version}' does not match '${cargo_version}'" \
      >&2
    exit 1
  fi
done

echo "Rust toolchain versions agree: ${cargo_version}"
