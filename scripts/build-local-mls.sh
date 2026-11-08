#!/usr/bin/env bash
# Build an internal, localhost-only PictoRust MLS preview bundle.
# Does not upload artifacts or publish any third-party assets.
set -euo pipefail
umask 077
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
command -v cargo >/dev/null || { echo 'Rust cargo is required' >&2; exit 1; }
command -v wasm-pack >/dev/null || { echo 'Install wasm-pack 0.13.1 first' >&2; exit 1; }
mkdir -p "$root/build"
cargo test --manifest-path mls-lab/Cargo.toml --test client_api
wasm-pack build mls-web --target web --release --out-dir pkg
test -s mls-web/pkg/pictorust_mls_web.js
test -s mls-web/pkg/pictorust_mls_web_bg.wasm
cargo test --manifest-path server/Cargo.toml --all-targets
cargo build --manifest-path server/Cargo.toml --release --bin pictochat-relay
bundle="$root/build/pictorust-mls-local"
mkdir -p "$bundle/mls"
install -m 0700 server/target/release/pictochat-relay "$bundle/pictochat-relay"
install -m 0600 mls-web/pkg/pictorust_mls_web.js "$bundle/mls/pictorust_mls_web.js"
install -m 0600 mls-web/pkg/pictorust_mls_web_bg.wasm "$bundle/mls/pictorust_mls_web_bg.wasm"
cat > "$bundle/run.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! "${PICTOCHAT_RELAY_SECRET:-}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo 'Set PICTOCHAT_RELAY_SECRET to a random 32-byte hexadecimal secret.' >&2
  echo 'Example for local testing: export PICTOCHAT_RELAY_SECRET="$(openssl rand -hex 32)"' >&2
  exit 1
fi
export PICTORUST_MLS_ASSETS="$dir/mls"
exec "$dir/pictochat-relay"
SCRIPT
chmod 0700 "$bundle/run.sh"
(cd "$bundle" && sha256sum pictochat-relay mls/pictorust_mls_web.js mls/pictorust_mls_web_bg.wasm > SHA256SUMS)
printf '\nLocal MLS bundle ready: %s\n' "$bundle"
printf 'Start: PICTOCHAT_RELAY_SECRET="$(openssl rand -hex 32)" %s/run.sh\n' "$bundle"
printf 'Check: curl -fsS http://127.0.0.1:8787/mls/healthz\n'
printf 'UI: http://127.0.0.1:8787/mls\n'
