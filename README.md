# mcpg-plugin — plugin artifact packaging and OCI distribution CLI

`mcpg-plugin` turns an already-built MCPG plugin binary into a signed,
packaged, verifiable OCI artifact that a gateway or the Kubernetes operator
can pull and load. It covers the supply-chain half of the plugin workflow —
hashing, Ed25519 detached signing, zip packaging, registry push/pull, local
cache hygiene, and a mock-gateway smoke test. Plugin authors and release
pipelines run it; the `mcpg` gateway binary dispatches `mcpg plugin <command>`
to it when it is on `$PATH` or sitting next to the `mcpg` executable.

Scope is deliberately narrow: compiling plugins (`cargo build`), generating
signing keys (`ssh-keygen -t ed25519` or any Ed25519 library), and chained
release automation stay with your own toolchain.

**Rust · Ed25519 detached signatures · OCI 1.1 artifacts · standalone binary or `mcpg plugin <command>`**

## What it does

- `new` — scaffolds a plugin crate (`Cargo.toml`, `plugin.yaml`, `src/lib.rs`
  wired to the `declare_plugin!` macro) for one of the supported plugin kinds.
- `pack` — bundles a `plugin.yaml` descriptor, the built artifact, an optional
  detached signature, and an optional `LICENSE` into the canonical zip.
- `unpack` — extracts a package, parses and schema-checks the descriptor, and
  prints the resolved id, class, runtime, and protocol version.
- `sign` — produces a 64-byte raw Ed25519 detached signature, either from a
  local key file or by delegating to an external KMS/HSM signer.
- `verify` — checks an artifact's SHA-256 and/or its Ed25519 signature, and
  exits non-zero when either check fails.
- `hash` — prints `sha256:<hex>` for an artifact plus the config snippet that
  pins it.
- `list` — lists plugin artifacts (`.so`, `.dylib`, `.dll`, `.wasm`) in a
  directory.
- `push` — publishes a package to an OCI 1.1 registry and prints the resolved
  manifest digest.
- `pull` — fetches a package from an OCI 1.1 registry, honouring a
  digest-pinned reference.
- `cache gc` — garbage-collects the local OCI unpack cache with conservative
  retention defaults.
- `test` — loads a packaged plugin into an in-process mock gateway and
  exercises its vtable contract, printing the plugin's response as JSON.

Run any subcommand with `--help` for its full option list. `list` and
`cache gc` have working defaults and simply run when given no arguments; the
rest print their usage.

## Install / Run

Build from source:

```bash
cargo build -p mcpg-plugin --release   # → target/release/mcpg-plugin
```

Put the binary on `$PATH` (or alongside the `mcpg` executable) and the gateway
CLI will forward to it:

```bash
mcpg plugin pack --descriptor plugin.yaml --artifact libmy_plugin.so --version 1.2.0
mcpg-plugin pack --descriptor plugin.yaml --artifact libmy_plugin.so --version 1.2.0
```

Both forms are identical — the first runs the second as a child process, with
the arguments, the environment, and the exit code passed straight through.

## Configuration

There is no config file. Behaviour comes from command flags, a small set of
environment variables, and the Docker credential store.

| Variable | Read by | Effect |
|---|---|---|
| `MCPG_PLUGIN_DIR` | `list` | Directory scanned when no path argument is given; falls back to the current directory. |
| `XDG_CACHE_HOME` | `cache gc` | Base of the default cache directory, `<XDG_CACHE_HOME>/mcpg/plugins/oci`. |
| `HOME` | `cache gc`, `push`, `pull` | Cache fallback `$HOME/.cache/mcpg/plugins/oci`, and the location of `~/.docker/config.json`. |
| `MCPG_SIGN_ARTIFACT` | set by `sign --subprocess` | Exported into the signer command's environment, holding the artifact path. |

With neither `XDG_CACHE_HOME` nor `HOME` set, the cache directory resolves to
`/var/cache/mcpg/plugins/oci` — the same resolution order the gateway uses, so
`cache gc` operates on the directory the gateway actually fills.

`--password env:VAR` reads the credential from the named environment variable,
so a registry secret never enters shell history.

## Package format

A packaged plugin is a zip archive:

```text
plugin.yaml    descriptor (required)
plugin.so      native cdylib artifact
plugin.wasm    wasm component artifact
plugin.sig     Ed25519 detached signature over the artifact (optional)
LICENSE        full licence text of the plugin's source licence (optional)
```

Exactly one of `plugin.so` / `plugin.wasm` must be present. Zip is the
container because it is inspectable with stock tooling on Linux, macOS, and
Windows — no MCPG-specific utility required to look inside a package.

`pack` infers the artifact kind from the extension: `.so`, `.dylib`, and `.dll`
are all native cdylibs (repacked under the canonical `plugin.so` entry name)
and `.wasm` is a wasm component. It names the output canonically:

```text
mcpg-plugin-<NAME>_<VERSION>_<OS>_<ARCH>.zip
```

`<NAME>` is the last `.`-separated segment of the descriptor id
(`circuit-breaker` from `dev.mcpg.circuit-breaker`), `<VERSION>` is the value
you pass to `--version`, and `<OS>`/`<ARCH>` default to the host build for
native artifacts and to `wasi`/`wasm` for components. Pass `--os` / `--arch` to
override, `--output` to choose a different filename. When `--license` is
omitted, a `LICENSE` sitting next to the descriptor is picked up automatically
so distributed artifacts carry their licence.

```bash
mcpg-plugin pack \
  --descriptor plugin.yaml \
  --artifact target/release/libmy_plugin.so \
  --signature target/release/libmy_plugin.so.sig \
  --version 1.2.0
```

## Signing and verification

`sign --key <file>` reads a **32-byte raw Ed25519 seed** (anything else is
rejected) and writes the raw 64-byte signature next to the artifact as
`<artifact>.sig`. It prints the artifact SHA-256 and the derived public key as
a receipt.

`sign --subprocess '<command>'` delegates to an external signer for
KMS- or HSM-resident keys. The command runs under `sh -c` (so a full pipeline
works as one argument) with `MCPG_SIGN_ARTIFACT` set to the artifact path, and
must write exactly 64 bytes of raw Ed25519 signature to stdout — trailing
newlines, hex, or base64 are rejected with an explicit error. The signing key
never reaches this process.

`--public-key <hex|file:path>` is **required** with `--subprocess`: the
signature is verified against that key before the `.sig` file is written, so a
wrong key version or key resource path fails at sign time rather than at
gateway load time.

`verify` checks whichever of the two properties you ask for and reports each
independently:

```bash
mcpg-plugin verify --key ./signing.pub --hash <expected-sha256> ./libmy_plugin.so
```

`--key` takes a 32-byte raw public key file. A failed check prints
`Verification: FAILED` and exits 1, so the command drops straight into a CI
gate.

## Registry authentication

`push` and `pull` resolve credentials in a fixed priority order:

1. `--username <user>` together with `--password <pw|env:VAR>` — both flags
   are required together.
2. `--docker-config <path>` — an explicit alternate `config.json`.
3. `~/.docker/config.json`, unless `--no-docker-config` was passed.
4. Anonymous.

A `config.json` that fails to parse produces a warning and falls back to
anonymous rather than aborting the transfer; pass `--no-docker-config` or
explicit credentials when you need that to be strict.

`localhost`, `127.0.0.1`, and `::1` are always treated as plain HTTP, following
Docker convention. For other development or air-gapped hosts, pass
`--insecure-registry <host[:port]>` (repeatable).

Packages are published as OCI 1.1 artifacts, not container images:

| Field | Value |
|---|---|
| manifest `mediaType` | `application/vnd.oci.image.manifest.v1+json` |
| config `mediaType` | `application/vnd.mcpg.plugin.config.v1+json` |
| layer `mediaType` | `application/vnd.mcpg.plugin.package.v1+zip` |
| `artifactType` | `application/vnd.mcpg.plugin.v1` |

`docker pull` rejects these, which is intentional. `push` prints a
machine-parseable `manifest-digest` line so release tooling can sign the pushed
manifest by digest instead of racing a tag-to-digest resolution. On the way
back, a reference pinned as `…@sha256:<hex>` is re-asserted against the
resolved manifest before the layer is written to disk.

```bash
mcpg-plugin push mcpg-plugin-my-plugin_1.2.0_linux_amd64.zip \
  ghcr.io/acme/plugins/my-plugin:1.2.0 \
  --username acme-ci --password env:GHCR_TOKEN
```

## Development

```bash
cargo build -p mcpg-plugin --release
cargo test  -p mcpg-plugin
```

The unit tests cover cache-GC planning, duration parsing, cache-entry grouping,
and a subprocess-signer round trip.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

## See also

- <https://mcpg.dev/docs/plugins/plugin-authoring> — writing a plugin, from
  scaffold to signed artifact.
- <https://mcpg.dev/docs/security/plugin-security> — signing, trust roots,
  revocation, and how the gateway verifies a plugin at load time.
- <https://mcpg.dev/docs/plugins/plugins-and-protocol> — plugin classes, the
  descriptor, and the ABI.
- <https://mcpg.dev/docs/reference/cli> — the `mcpg` CLI this binary plugs
  into.
