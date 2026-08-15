//! mcpg-plugin — plugin artifact file-management CLI.
//!
//! Scoped to plugin artifact file management:
//! takes already-built plugin binaries and turns them into signed,
//! packaged, distributable, verifiable OCI artifacts. Developer tooling —
//! compiling plugins, generating signing keys, scaffolding new crates,
//! chained release automation — is deliberately out of scope and handled
//! by each plugin project's own toolchain.
//!
//! - `hash`     — Compute SHA-256 of an artifact
//! - `sign`     — Create Ed25519 detached signature (private key provided)
//! - `verify`   — Verify signature and/or hash
//! - `list`     — List plugin artifacts in a local directory
//! - `pack`     — Bundle descriptor + artifact + optional signature + optional
//!   LICENSE into ZIP
//! - `unpack`   — Extract a packaged plugin archive
//! - `push`     — Publish to an OCI registry
//! - `pull`     — Fetch from an OCI registry
//! - `cache gc` — Garbage-collect the local OCI unpack cache
//! - `test`     — Load a packaged plugin into an in-process mock gateway
//!   and exercise its vtable contract

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "mcpg-plugin",
    version,
    about = "Plugin artifact file-management CLI",
    long_about = "Plugin artifact file management: \
                  takes already-built plugin binaries and turns them into signed, \
                  packaged, distributable, verifiable OCI artifacts.\n\n\
                  Out of scope (handled by your own toolchain): compiling plugins \
                  (cargo build), generating signing keys (ssh-keygen -t ed25519), and \
                  chained release automation.\n\n\
                  Typically invoked via `mcpg plugin <command>`; runs directly as \
                  `mcpg-plugin <command>` too."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

// Each variant hands its raw arguments to the existing command fn, which
// owns the argument contract (and prints its full usage when invoked
// empty/wrong). `-h`/`--help` after the subcommand word is intercepted in
// `main` and renders clap's per-subcommand help, so every command has a
// working help.
#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scaffold a new plugin crate
    #[command(
        disable_help_flag = true,
        long_about = "Scaffold a working plugin crate with the unified declare_plugin! \
                      macro pre-wired, a sibling plugin.yaml matching the in-code \
                      manifest, and a single-source Cargo.toml ready for both cdylib \
                      OCI distribution and static-firstparty embedding.\n\n\
                      Usage: mcpg plugin new --kind <K> --name <N> [--id <ID>] [--out <DIR>]"
    )]
    New {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Load a packaged plugin and exercise its vtable contract
    #[command(
        disable_help_flag = true,
        long_about = "Load a packaged plugin into an in-process mock gateway and \
                      exercise its vtable contract.\n\n\
                      Usage: mcpg plugin test <archive.zip> [options] \
                      (run with no arguments for the full option list)"
    )]
    Test {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Bundle descriptor + artifact + optional signature/license into a package
    #[command(
        disable_help_flag = true,
        long_about = "Bundle a plugin.yaml descriptor + built artifact (+ optional \
                      detached signature + optional LICENSE text) into a \
                      distributable package.\n\n\
                      Usage: mcpg plugin pack … (run with no arguments for the full \
                      option list)"
    )]
    Pack {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Extract a packaged plugin archive
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin unpack <archive> <target-dir>"
    )]
    Unpack {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Create an Ed25519 detached signature (private key provided)
    #[command(
        disable_help_flag = true,
        long_about = "Create an Ed25519 detached signature over an artifact, with the \
                      key supplied directly (--key <private-key-file>) or via an \
                      external signer (--subprocess <cmd>)."
    )]
    Sign {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Verify artifact signature and/or hash
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin verify [--key <public-key-file>] \
                      [--hash <expected-sha256>] <artifact>"
    )]
    Verify {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Compute SHA-256 of an artifact
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin hash <artifact>"
    )]
    Hash {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// List plugin artifacts in a local directory
    #[command(
        disable_help_flag = true,
        long_about = "List plugin artifacts in a directory (defaults to \
                      MCPG_PLUGIN_DIR, falling back to the current directory)."
    )]
    List {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Publish a packaged plugin to an OCI registry
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin push <archive.zip> <registry/repo:tag> … \
                      (run with no arguments for the credential options)"
    )]
    Push {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Fetch a packaged plugin from an OCI registry
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin pull <registry/repo:tag> … \
                      (run with no arguments for the credential options)"
    )]
    Pull {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Manage the local OCI unpack cache
    Cache {
        #[command(subcommand)]
        cmd: CacheCmd,
    },
}

#[derive(Subcommand, Debug)]
enum CacheCmd {
    /// Garbage-collect the local OCI unpack cache
    #[command(
        disable_help_flag = true,
        long_about = "Usage: mcpg plugin cache gc [options] \
                      (run with --dry-run first; run with no arguments for the \
                      retention options)"
    )]
    Gc {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "--help" || a == "-h")
}

/// Render clap's help for a (possibly nested) subcommand path.
fn print_sub_help(path: &[&str]) {
    let mut cmd = Cli::command();
    let mut cur = &mut cmd;
    for name in path {
        match cur.find_subcommand_mut(name) {
            Some(sc) => cur = sc,
            None => return,
        }
    }
    let _ = cur.print_long_help();
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // (sub-path for help rendering, raw args, the command fn)
    type Runner = fn(&[String]) -> anyhow::Result<()>;
    let (path, args, runner): (&[&str], Vec<String>, Runner) = match cli.command {
        Cmd::New { args } => (&["new"], args, cmd_new),
        Cmd::Test { args } => (&["test"], args, cmd_test),
        Cmd::Pack { args } => (&["pack"], args, cmd_pack),
        Cmd::Unpack { args } => (&["unpack"], args, cmd_unpack),
        Cmd::Sign { args } => (&["sign"], args, cmd_sign),
        Cmd::Verify { args } => (&["verify"], args, cmd_verify),
        Cmd::Hash { args } => (&["hash"], args, cmd_hash),
        Cmd::List { args } => (&["list"], args, cmd_list),
        Cmd::Push { args } => (&["push"], args, cmd_push),
        Cmd::Pull { args } => (&["pull"], args, cmd_pull),
        Cmd::Cache {
            cmd: CacheCmd::Gc { args },
        } => (&["cache", "gc"], args, cmd_cache_gc),
    };

    if wants_help(&args) {
        print_sub_help(path);
        return ExitCode::SUCCESS;
    }

    match runner(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// hash — compute SHA-256 of an artifact
// ---------------------------------------------------------------------------

fn cmd_hash(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mcpg-plugin hash <artifact>");
        eprintln!();
        eprintln!("Compute the SHA-256 hash of a plugin artifact.");
        eprintln!("Output can be used in config integrity.sha256 fields.");
        return Ok(());
    }

    let path = PathBuf::from(&args[0]);
    if !path.exists() {
        return Err(anyhow::anyhow!("file not found: {}", path.display()));
    }

    let hash = mcpg_plugin_host::verify::sha256_file(&path)?;
    println!("sha256:{}", hash);
    println!();
    println!("# Add to plugin config:");
    println!("#   integrity:");
    println!("#     sha256: \"{}\"", hash);
    Ok(())
}

// ---------------------------------------------------------------------------
// sign — create Ed25519 detached signature
// ---------------------------------------------------------------------------

fn cmd_sign(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage:");
        eprintln!("  mcpg-plugin sign --key <private-key-file> <artifact>");
        eprintln!("  mcpg-plugin sign --subprocess <command> [--public-key <hex>] <artifact>");
        eprintln!();
        eprintln!("Create an Ed25519 detached signature for a native plugin artifact.");
        eprintln!("The signature (raw 64 bytes) is written to <artifact>.<ext>.sig.");
        eprintln!();
        eprintln!("Signers:");
        eprintln!("  --key <file>          Read a 32-byte raw Ed25519 seed from <file>");
        eprintln!("                        and sign locally. Default mode.");
        eprintln!("  --subprocess <cmd>    Delegate signing to an external command");
        eprintln!("                        (cloud KMS, HSM, etc.). The command is");
        eprintln!("                        executed with `MCPG_SIGN_ARTIFACT` set to");
        eprintln!("                        the artifact path; it MUST write exactly");
        eprintln!("                        64 bytes of raw Ed25519 signature to its");
        eprintln!("                        stdout. The subprocess never sees the");
        eprintln!("                        signing key — that's KMS-resident.");
        eprintln!("  --public-key <hex>    Optional. With --subprocess, the");
        eprintln!("                        hex-encoded 32-byte public key the");
        eprintln!("                        produced signature should verify against;");
        eprintln!("                        the CLI cross-checks before writing the");
        eprintln!("                        signature file (catches KMS misconfig at");
        eprintln!("                        sign time, not load time). May also be");
        eprintln!("                        a path to a 32-byte raw or hex-encoded");
        eprintln!("                        file via `file:<path>`.");
        return Ok(());
    }

    let parsed = parse_sign_args(args)?;
    let artifact_path = parsed.artifact;
    let artifact_data = std::fs::read(&artifact_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read artifact '{}': {}",
            artifact_path.display(),
            e
        )
    })?;

    let (signature_bytes, public_key_hex) = match parsed.signer {
        SignerKind::Local { key_path } => sign_local(&key_path, &artifact_data)?,
        SignerKind::Subprocess {
            command,
            public_key,
        } => sign_subprocess(
            &command,
            &artifact_path,
            &artifact_data,
            public_key.as_deref(),
        )?,
    };

    let sig_path = artifact_path.with_extension(format!(
        "{}.sig",
        artifact_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
    ));
    std::fs::write(&sig_path, &signature_bytes).map_err(|e| {
        anyhow::anyhow!("failed to write signature '{}': {}", sig_path.display(), e)
    })?;

    let hash = mcpg_plugin_host::verify::sha256_hex(&artifact_data);
    println!("Signed: {}", artifact_path.display());
    println!("  Signature: {}", sig_path.display());
    println!("  SHA-256:   {}", hash);
    println!("  Public key: {}", public_key_hex);

    Ok(())
}

#[derive(Debug)]
enum SignerKind {
    Local {
        key_path: PathBuf,
    },
    Subprocess {
        command: String,
        public_key: Option<String>,
    },
}

#[derive(Debug)]
struct SignArgs {
    signer: SignerKind,
    artifact: PathBuf,
}

fn parse_sign_args(args: &[String]) -> anyhow::Result<SignArgs> {
    let mut key_path: Option<PathBuf> = None;
    let mut subprocess_cmd: Option<String> = None;
    let mut public_key: Option<String> = None;
    let mut artifact_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                key_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--key requires a value"))?,
                ));
            }
            "--subprocess" => {
                i += 1;
                subprocess_cmd = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--subprocess requires a command string"))?
                        .clone(),
                );
            }
            "--public-key" => {
                i += 1;
                public_key = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--public-key requires a value"))?
                        .clone(),
                );
            }
            _ => {
                artifact_path = Some(PathBuf::from(&args[i]));
            }
        }
        i += 1;
    }

    let artifact = artifact_path.ok_or_else(|| anyhow::anyhow!("artifact path is required"))?;

    let signer = match (key_path, subprocess_cmd) {
        (Some(_), Some(_)) => {
            return Err(anyhow::anyhow!(
                "--key and --subprocess are mutually exclusive — pick one signer"
            ));
        }
        (Some(key_path), None) => {
            if public_key.is_some() {
                return Err(anyhow::anyhow!(
                    "--public-key only applies to --subprocess (the local signer \
                     derives the public key from the seed automatically)"
                ));
            }
            SignerKind::Local { key_path }
        }
        (None, Some(command)) => SignerKind::Subprocess {
            command,
            public_key,
        },
        (None, None) => {
            return Err(anyhow::anyhow!(
                "either --key <file> (local signer) or --subprocess <cmd> (KMS / HSM signer) is required"
            ));
        }
    };

    Ok(SignArgs { signer, artifact })
}

fn sign_local(key_path: &Path, artifact_data: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
    let key_bytes = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("failed to read key file '{}': {}", key_path.display(), e))?;
    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "key file must be exactly 32 bytes (raw Ed25519 seed), got {} bytes",
            key_bytes.len()
        ));
    }
    let key_array: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(artifact_data);
    Ok((
        signature.to_bytes().to_vec(),
        hex::encode(signing_key.verifying_key().as_bytes()),
    ))
}

fn sign_subprocess(
    command: &str,
    artifact_path: &Path,
    artifact_data: &[u8],
    declared_public_key: Option<&str>,
) -> anyhow::Result<(Vec<u8>, String)> {
    use std::process::{Command, Stdio};

    // Run via `sh -c` so operators can pass full pipelines as a
    // single string arg (`gcloud kms sign … | tail -c 64`). This
    // matches every other CI signer (`gh release`, etc.).
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .env("MCPG_SIGN_ARTIFACT", artifact_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| anyhow::anyhow!("subprocess signer '{command}' failed to spawn: {e}"))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "subprocess signer '{command}' exited with status {}",
            output.status
        ));
    }

    let signature_bytes = output.stdout;
    if signature_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "subprocess signer must emit exactly 64 bytes of raw Ed25519 signature \
             on stdout, got {} bytes — check that the signer doesn't print \
             trailing newlines / hex / base64",
            signature_bytes.len()
        ));
    }

    // Resolve the declared public key (literal hex or `file:<path>`).
    // We always need *some* public key for the printed receipt + the
    // local cross-check; mandate it for subprocess signers because
    // the CLI can't derive the pubkey from a remote KMS-held seed.
    let public_key_hex = match declared_public_key {
        Some(s) => resolve_public_key(s)?,
        None => {
            return Err(anyhow::anyhow!(
                "--public-key <hex|file:path> is required when using --subprocess \
                 (the CLI verifies the produced signature against this key before \
                 writing the .sig file, catching KMS misconfig at sign time)"
            ));
        }
    };

    // Decode + cross-verify so a misconfigured KMS (wrong key
    // version, wrong key resource path) fails at sign time instead
    // of at gateway-load time.
    let pubkey_bytes = hex::decode(&public_key_hex)
        .map_err(|e| anyhow::anyhow!("--public-key hex decode: {e}"))?;
    if pubkey_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "--public-key must be 32 raw bytes (hex-encoded), got {} bytes",
            pubkey_bytes.len()
        ));
    }
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into().unwrap();
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| anyhow::anyhow!("--public-key isn't a valid Ed25519 verifying key: {e}"))?;
    let sig_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .expect("checked == 64 above");
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(artifact_data, &signature)
        .map_err(|e| {
            anyhow::anyhow!(
                "subprocess signer produced a signature that does NOT verify against \
             the declared --public-key. Either the KMS / signer is misconfigured \
             or --public-key is wrong. (verifier error: {e})"
            )
        })?;

    Ok((signature_bytes, public_key_hex))
}

fn resolve_public_key(value: &str) -> anyhow::Result<String> {
    // `file:<path>` — read 32 raw bytes OR a hex-encoded 64-char
    // string (with or without trailing newline) from disk and
    // hex-encode if needed. Bare `<hex>` — return as-is after
    // sanity-stripping whitespace / 0x prefix.
    if let Some(path) = value.strip_prefix("file:") {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read --public-key file '{}': {}", path, e))?;
        // Trim trailing whitespace if it looks like text.
        let trimmed = std::str::from_utf8(&bytes)
            .ok()
            .map(|s| s.trim().trim_start_matches("0x"));
        if let Some(text) = trimmed
            && text.len() == 64
            && text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Ok(text.to_ascii_lowercase());
        }
        if bytes.len() == 32 {
            return Ok(hex::encode(&bytes));
        }
        return Err(anyhow::anyhow!(
            "--public-key file '{}' must be either 32 raw bytes or a 64-char \
             hex string (with optional `0x` prefix and trailing newline)",
            path
        ));
    }
    let cleaned = value.trim().trim_start_matches("0x").to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "--public-key must be 64 hex chars (or `file:<path>`)"
        ));
    }
    Ok(cleaned)
}

// ---------------------------------------------------------------------------
// verify — check signature and/or hash
// ---------------------------------------------------------------------------

fn cmd_verify(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!(
            "Usage: mcpg-plugin verify [--key <public-key-file>] [--hash <expected-sha256>] <artifact>"
        );
        eprintln!();
        eprintln!("Verify a plugin artifact's integrity:");
        eprintln!("  --key <file>   Check Ed25519 signature against this public key (32 bytes)");
        eprintln!("  --hash <hex>   Check SHA-256 hash matches expected value");
        return Ok(());
    }

    let mut public_key_path: Option<PathBuf> = None;
    let mut expected_hash: Option<String> = None;
    let mut artifact_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                public_key_path = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--key requires a value"))?,
                ));
            }
            "--hash" => {
                i += 1;
                expected_hash = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--hash requires a value"))?
                        .clone(),
                );
            }
            _ => {
                artifact_path = Some(PathBuf::from(&args[i]));
            }
        }
        i += 1;
    }

    let artifact_path =
        artifact_path.ok_or_else(|| anyhow::anyhow!("no artifact path specified"))?;
    if !artifact_path.exists() {
        return Err(anyhow::anyhow!(
            "artifact not found: {}",
            artifact_path.display()
        ));
    }

    let mut all_ok = true;

    // Hash check
    let actual_hash = mcpg_plugin_host::verify::sha256_file(&artifact_path)?;
    if let Some(expected) = &expected_hash {
        if actual_hash == *expected {
            println!("  [OK] SHA-256: {}", actual_hash);
        } else {
            println!(
                "  [FAIL] SHA-256: expected {}, got {}",
                expected, actual_hash
            );
            all_ok = false;
        }
    } else {
        println!("  SHA-256: {}", actual_hash);
    }

    // Signature check
    if let Some(key_path) = &public_key_path {
        let key_bytes = std::fs::read(key_path).map_err(|e| {
            anyhow::anyhow!("failed to read public key '{}': {}", key_path.display(), e)
        })?;
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "public key must be exactly 32 bytes, got {}",
                key_bytes.len()
            ));
        }
        let key_array: [u8; 32] = key_bytes.try_into().unwrap();
        match mcpg_plugin_host::verify::verify_file_signature(&artifact_path, &key_array) {
            Ok(true) => println!("  [OK] Ed25519 signature verified"),
            Ok(false) => {
                println!("  [FAIL] Ed25519 signature does not match");
                all_ok = false;
            }
            Err(e) => {
                println!("  [FAIL] Signature check error: {}", e);
                all_ok = false;
            }
        }
    }

    if all_ok {
        println!("\nVerification: PASSED");
    } else {
        println!("\nVerification: FAILED");
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// list — list plugins in a directory
// ---------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> anyhow::Result<()> {
    let dir = args.first().map(PathBuf::from).unwrap_or_else(|| {
        std::env::var("MCPG_PLUGIN_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    });

    if !dir.is_dir() {
        return Err(anyhow::anyhow!("not a directory: {}", dir.display()));
    }

    println!("Plugins in {}:", dir.display());
    println!();

    let mut found = 0;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();

        let is_plugin = name.ends_with(".so")
            || name.ends_with(".dylib")
            || name.ends_with(".dll")
            || name.ends_with(".wasm");

        if !is_plugin {
            continue;
        }

        let hash = mcpg_plugin_host::verify::sha256_file(&path)?;
        let has_sig = path
            .with_extension(format!(
                "{}.sig",
                path.extension().and_then(|e| e.to_str()).unwrap_or("bin")
            ))
            .exists();

        let kind = if name.ends_with(".wasm") {
            "wasm"
        } else {
            "native"
        };

        println!(
            "  {} ({}) sha256:{}{}",
            name,
            kind,
            &hash[..16],
            if has_sig { " [signed]" } else { "" }
        );
        found += 1;
    }

    if found == 0 {
        println!("  (no plugin artifacts found)");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// pack — bundle a plugin into a distributable .mcpg-plugin.tar.gz archive
// ---------------------------------------------------------------------------

fn cmd_pack(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mcpg-plugin pack \\");
        eprintln!("    --descriptor <plugin.yaml> \\");
        eprintln!("    --artifact <plugin.so|plugin.wasm> \\");
        eprintln!("    --version <plugin-version> \\");
        eprintln!("    [--signature <plugin.sig>] \\");
        eprintln!("    [--license <LICENSE>] \\");
        eprintln!("    [--os <linux|darwin|windows|wasi>] \\");
        eprintln!("    [--arch <amd64|arm64|wasm>] \\");
        eprintln!("    [--output <path>]");
        eprintln!();
        eprintln!("Bundle a plugin's descriptor, artifact, optional signature, and optional");
        eprintln!("license text into a distributable zip archive.");
        eprintln!();
        eprintln!("When --license is omitted, a LICENSE file sitting next to the descriptor");
        eprintln!("is included automatically so distributed artifacts carry their license.");
        eprintln!();
        eprintln!("Output filename defaults to the canonical form:");
        eprintln!("  mcpg-plugin-<NAME>_<VERSION>_<OS>_<ARCH>.zip");
        eprintln!();
        eprintln!("where NAME is the last '.'-separated segment of the plugin id in the");
        eprintln!("descriptor (e.g. 'circuit-breaker' from 'dev.mcpg.circuit-breaker').");
        eprintln!();
        eprintln!("Artifact kind (native vs wasm) is inferred from the extension:");
        eprintln!("  *.so, *.dylib, *.dll → native-cdylib-v1  (default OS/ARCH = host build)");
        eprintln!("  *.wasm        → wasi-v1           (default OS/ARCH = wasi/wasm)");
        return Ok(());
    }

    let mut descriptor_p: Option<PathBuf> = None;
    let mut artifact_p: Option<PathBuf> = None;
    let mut signature_p: Option<PathBuf> = None;
    let mut license_p: Option<PathBuf> = None;
    let mut output_p: Option<PathBuf> = None;
    let mut version_v: Option<String> = None;
    let mut os_v: Option<String> = None;
    let mut arch_v: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" | "-d" => {
                descriptor_p =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--descriptor requires a path argument")
                    })?));
                i += 2;
            }
            "--artifact" | "-a" => {
                artifact_p =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--artifact requires a path argument")
                    })?));
                i += 2;
            }
            "--signature" | "-s" => {
                signature_p =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--signature requires a path argument")
                    })?));
                i += 2;
            }
            "--license" | "-l" => {
                license_p =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--license requires a path argument")
                    })?));
                i += 2;
            }
            "--output" | "-o" => {
                output_p =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--output requires a path argument")
                    })?));
                i += 2;
            }
            "--version" | "-v" => {
                version_v = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--version requires a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--os" => {
                os_v = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--os requires a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--arch" => {
                arch_v = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--arch requires a value"))?
                        .clone(),
                );
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!("unknown option: {other}"));
            }
        }
    }

    let descriptor_p = descriptor_p.ok_or_else(|| anyhow::anyhow!("--descriptor is required"))?;
    let artifact_p = artifact_p.ok_or_else(|| anyhow::anyhow!("--artifact is required"))?;
    let version_v = version_v.ok_or_else(|| anyhow::anyhow!("--version is required"))?;

    let artifact_kind = match artifact_p.extension().and_then(|e| e.to_str()) {
        // .so (linux gnu/musl), .dylib (macOS), .dll (windows) are all native
        // cdylibs → repacked under the canonical `plugin.so` entry name.
        Some("so") | Some("dylib") | Some("dll") => mcpg_plugin_host::package::ArtifactKind::Native,
        Some("wasm") => mcpg_plugin_host::package::ArtifactKind::Wasm,
        _ => {
            return Err(anyhow::anyhow!(
                "cannot infer artifact kind from {} — expected .so/.dylib/.dll or .wasm",
                artifact_p.display()
            ));
        }
    };

    // Derive default os/arch from the artifact kind. For native,
    // fall back to the host build target so a dev running
    // `cargo run` on linux/amd64 gets a sensible default. For
    // wasm, platform is always wasi/wasm.
    let (default_os, default_arch) = match artifact_kind {
        mcpg_plugin_host::package::ArtifactKind::Native => (host_os_label(), host_arch_label()),
        mcpg_plugin_host::package::ArtifactKind::Wasm => ("wasi", "wasm"),
    };
    let os = os_v.as_deref().unwrap_or(default_os);
    let arch = arch_v.as_deref().unwrap_or(default_arch);

    // Parse descriptor to derive short name for the canonical
    // filename. We reuse the host's load_descriptor so schema is
    // also validated up front.
    let desc = mcpg_plugin_host::load_descriptor(&descriptor_p)?;
    let short = mcpg_plugin_host::short_name_from_id(&desc.id);

    // A LICENSE file next to the descriptor (the plugin crate root)
    // is bundled automatically; --license points elsewhere.
    let license_p = license_p.or_else(|| {
        let candidate = descriptor_p.parent()?.join("LICENSE");
        candidate.is_file().then_some(candidate)
    });

    let output_p = output_p.unwrap_or_else(|| {
        PathBuf::from(mcpg_plugin_host::canonical_filename(
            short, &version_v, os, arch,
        ))
    });

    mcpg_plugin_host::Package::pack(
        &mcpg_plugin_host::PackInputs {
            descriptor_path: &descriptor_p,
            artifact_path: &artifact_p,
            artifact_kind,
            signature_path: signature_p.as_deref(),
            license_path: license_p.as_deref(),
        },
        &output_p,
    )?;

    let size = std::fs::metadata(&output_p).map(|m| m.len()).unwrap_or(0);
    println!("packed: {} ({} bytes)", output_p.display(), size);
    Ok(())
}

// ---------------------------------------------------------------------------
// push — publish a packaged plugin to an OCI registry
// ---------------------------------------------------------------------------

fn cmd_push(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mcpg-plugin push <archive.zip> <registry/repo:tag> \\");
        eprintln!("    [--username <user>] [--password <pw-or-env>] \\");
        eprintln!("    [--docker-config <path>] [--no-docker-config] \\");
        eprintln!("    [--insecure-registry <host[:port]>]...");
        eprintln!();
        eprintln!("Publish a packaged plugin to an OCI 1.1 registry (GHCR, Docker Hub,");
        eprintln!("Harbor, ECR, Artifactory 7.6+, Zot, ...). The zip is wrapped as an");
        eprintln!("OCI artifact with:");
        eprintln!("  manifest mediaType = application/vnd.oci.image.manifest.v1+json");
        eprintln!("    config mediaType = application/vnd.mcpg.plugin.config.v1+json");
        eprintln!("    layer  mediaType = application/vnd.mcpg.plugin.package.v1+zip");
        eprintln!("    artifactType     = application/vnd.mcpg.plugin.v1");
        eprintln!();
        eprintln!("`docker pull` will reject these (the config mediaType is not a container");
        eprintln!("image config), which is intentional — they are not containers.");
        eprintln!();
        eprintln!("Authentication, in priority order:");
        eprintln!("  1. --username <user> + --password <pw-or-env:VAR>");
        eprintln!("  2. --docker-config <path>  (explicit alternate config.json)");
        eprintln!("  3. ~/.docker/config.json   (auto, unless --no-docker-config)");
        eprintln!("  4. anonymous");
        eprintln!();
        eprintln!("`localhost`, `127.0.0.1`, and `::1` are always plain-HTTP (Docker");
        eprintln!("convention). Pass `--insecure-registry` for other dev / air-gap hosts.");
        return Ok(());
    }
    if args.len() < 2 {
        return Err(anyhow::anyhow!(
            "push requires <archive> <registry/repo:tag>"
        ));
    }
    let archive = PathBuf::from(&args[0]);
    let reference = args[1].clone();

    let push_opts = parse_push_pull_options(&args[2..])?;
    let auth = resolve_push_pull_auth(&reference, &push_opts)?;
    let options = mcpg_plugin_host::oci::OciClientOptions {
        insecure_registries: push_opts.insecure,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let outcome = rt.block_on(mcpg_plugin_host::oci::push(
        &archive, &reference, auth, options,
    ))?;
    println!("pushed: {}", reference);
    println!("  manifest-url: {}", outcome.manifest_url);
    // Machine-parseable digest line — release tooling signs the pushed
    // manifest BY DIGEST (tag→digest resolution at sign time is a race).
    println!("  manifest-digest: {}", outcome.manifest_digest);
    Ok(())
}

// ---------------------------------------------------------------------------
// pull — fetch a packaged plugin from an OCI registry
// ---------------------------------------------------------------------------

fn cmd_pull(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mcpg-plugin pull <registry/repo:tag> \\");
        eprintln!("    [--output <path>] \\");
        eprintln!("    [--username <user>] [--password <pw-or-env>] \\");
        eprintln!("    [--docker-config <path>] [--no-docker-config] \\");
        eprintln!("    [--insecure-registry <host[:port]>]...");
        eprintln!();
        eprintln!("Fetch a packaged plugin from an OCI 1.1 registry and write it to");
        eprintln!("disk. Output defaults to <repo>_<tag>.zip in CWD.");
        eprintln!();
        eprintln!("Authentication, in priority order:");
        eprintln!("  1. --username <user> + --password <pw-or-env:VAR>");
        eprintln!("  2. --docker-config <path>  (explicit alternate config.json)");
        eprintln!("  3. ~/.docker/config.json   (auto, unless --no-docker-config)");
        eprintln!("  4. anonymous");
        eprintln!();
        eprintln!("`localhost`, `127.0.0.1`, and `::1` are always plain-HTTP (Docker");
        eprintln!("convention). Pass `--insecure-registry` for other dev / air-gap hosts.");
        return Ok(());
    }
    let reference = args[0].clone();

    let mut output: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                output = Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                    anyhow::anyhow!("--output requires a path argument")
                })?));
                i += 2;
            }
            // Remaining flags handled by the shared parser below.
            _ => break,
        }
    }
    let push_opts = parse_push_pull_options(&args[i..])?;
    let auth = resolve_push_pull_auth(&reference, &push_opts)?;
    let options = mcpg_plugin_host::oci::OciClientOptions {
        insecure_registries: push_opts.insecure,
    };

    let output = output.unwrap_or_else(|| default_pull_output_path(&reference));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Re-assert a digest-pinned reference (`…@sha256:<hex>`) against the
    // resolved manifest before the layer is written.
    let pinned_digest = reference.rsplit_once("@sha256:").map(|(_, hex)| hex);
    let outcome = rt.block_on(mcpg_plugin_host::oci::pull(
        &reference,
        &output,
        auth,
        options,
        pinned_digest,
    ))?;

    println!("pulled: {}", reference);
    println!("  written:  {}", outcome.output_path.display());
    println!("  digest:   {}", outcome.manifest_digest);
    if let Some(cfg) = outcome.config {
        println!("  id:       {}", cfg.id);
        println!("  class:    {}", cfg.class);
        println!("  runtime:  {}", cfg.runtime);
        println!("  protocol: {}", cfg.protocol_version);
    }
    Ok(())
}

/// Parsed auth-related flags for `push` / `pull`.
struct PushPullOptions {
    username: Option<String>,
    password: Option<String>,
    /// Path to an alternate docker `config.json`. `None` means "look
    /// up `$HOME/.docker/config.json` if neither `--username` nor
    /// `--password` was set"; `Some(path)` forces that path even if
    /// env fallback would have found another.
    docker_config: Option<PathBuf>,
    /// When true, disables the auto-consult of `~/.docker/config.json`.
    /// Operators use this for testing or pipelines where they want
    /// purely anonymous auth.
    no_docker_config: bool,
    insecure: Vec<String>,
}

/// Parse `--username`, `--password`, `--docker-config`, `--no-docker-config`,
/// and repeatable `--insecure-registry` from a slice of args.
///
/// `--password` supports `env:VAR` to read from the environment so shell
/// history never sees the literal secret.
fn parse_push_pull_options(args: &[String]) -> anyhow::Result<PushPullOptions> {
    let mut out = PushPullOptions {
        username: None,
        password: None,
        docker_config: None,
        no_docker_config: false,
        insecure: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--username" | "-u" => {
                out.username = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--username requires a value"))?
                        .clone(),
                );
                i += 2;
            }
            "--password" | "-p" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--password requires a value"))?;
                out.password = Some(if let Some(var) = raw.strip_prefix("env:") {
                    std::env::var(var).map_err(|_| anyhow::anyhow!("env var {} not set", var))?
                } else {
                    raw.clone()
                });
                i += 2;
            }
            "--docker-config" => {
                out.docker_config =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--docker-config requires a path")
                    })?));
                i += 2;
            }
            "--no-docker-config" => {
                out.no_docker_config = true;
                i += 1;
            }
            "--insecure-registry" => {
                out.insecure.push(
                    args.get(i + 1)
                        .ok_or_else(|| {
                            anyhow::anyhow!("--insecure-registry requires a host[:port]")
                        })?
                        .clone(),
                );
                i += 2;
            }
            other => {
                return Err(anyhow::anyhow!("unknown option: {other}"));
            }
        }
    }
    Ok(out)
}

/// Resolve registry credentials for `reference` by walking a chain of
/// sources in decreasing priority:
///
/// 1. `--username` + `--password` CLI flags (both required together).
/// 2. The docker `config.json` at `--docker-config <path>`, if set.
/// 3. The default docker `config.json` at `~/.docker/config.json`,
///    *unless* `--no-docker-config` was passed.
/// 4. Anonymous.
fn resolve_push_pull_auth(
    reference: &str,
    opts: &PushPullOptions,
) -> anyhow::Result<mcpg_plugin_host::oci::OciAuth> {
    match (&opts.username, &opts.password) {
        (Some(u), Some(p)) => {
            return Ok(mcpg_plugin_host::oci::OciAuth::Basic {
                username: u.clone(),
                password: p.clone(),
            });
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--username and --password must be supplied together");
        }
        (None, None) => {}
    }

    if opts.no_docker_config {
        return Ok(mcpg_plugin_host::oci::OciAuth::Anonymous);
    }

    let host = registry_host_from_reference(reference);
    let docker_path = opts.docker_config.as_deref();
    match mcpg_plugin_host::docker_credentials::resolve_from_docker_config(&host, docker_path) {
        Ok(Some(auth)) => Ok(auth),
        Ok(None) => Ok(mcpg_plugin_host::oci::OciAuth::Anonymous),
        Err(e) => {
            // Surface the docker-config error to stderr but don't fail
            // the push/pull — fall through to anonymous. An operator
            // who wanted stricter behaviour can pass
            // `--no-docker-config` or explicit `--username`/`--password`.
            eprintln!("warning: docker config resolution failed: {e}");
            eprintln!("         falling back to anonymous; use --username/--password to override");
            Ok(mcpg_plugin_host::oci::OciAuth::Anonymous)
        }
    }
}

/// Extract the registry host from an OCI reference. Same logic as the
/// gateway's `registry_host_from_reference` — duplicated here (short
/// function, different crate) rather than added to plugin-host's public
/// surface, to keep the auth-resolution detail an implementation
/// concern of each caller.
fn registry_host_from_reference(reference: &str) -> String {
    let stripped = reference
        .strip_prefix("https://")
        .or_else(|| reference.strip_prefix("http://"))
        .unwrap_or(reference);
    stripped
        .split_once('/')
        .map(|(host, _)| host.to_owned())
        .unwrap_or_else(|| stripped.to_owned())
}

/// Build a sensible default output path from a registry reference
/// like `ghcr.io/org/plugin:1.0.0` → `plugin_1.0.0.zip` in CWD.
fn default_pull_output_path(reference: &str) -> PathBuf {
    let (repo_part, tag_part) = reference.rsplit_once(':').unwrap_or((reference, "latest"));
    let short_repo = repo_part.rsplit('/').next().unwrap_or(repo_part);
    PathBuf::from(format!("{short_repo}_{tag_part}.zip"))
}

// ---------------------------------------------------------------------------

/// Host OS label matching the `<OS>` slot in canonical filenames.
/// Maps Rust's `cfg(target_os)` values to the short labels we use.
const fn host_os_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

/// Host arch label matching the `<ARCH>` slot in canonical filenames.
const fn host_arch_label() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// unpack — extract a .mcpg-plugin.tar.gz archive
// ---------------------------------------------------------------------------

fn cmd_unpack(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mcpg-plugin unpack <archive.mcpg-plugin.tar.gz> <target-dir>");
        eprintln!();
        eprintln!("Extract a packaged plugin into the target directory.");
        eprintln!("The descriptor is parsed and schema-checked; malformed archives fail");
        eprintln!("with a structured error (missing descriptor, ambiguous artifact, etc.).");
        return Ok(());
    }
    if args.len() < 2 {
        return Err(anyhow::anyhow!("unpack requires <archive> <target-dir>"));
    }
    let archive = PathBuf::from(&args[0]);
    let target = PathBuf::from(&args[1]);

    let unpacked = mcpg_plugin_host::Package::unpack_to(&archive, &target)?;

    println!("unpacked: {}", archive.display());
    println!("  target:     {}", target.display());
    println!("  id:         {}", unpacked.descriptor.id);
    println!("  name:       {}", unpacked.descriptor.name);
    println!("  class:      {}", unpacked.descriptor.class);
    println!("  runtime:    {}", unpacked.descriptor.runtime);
    println!("  protocol:   {}", unpacked.descriptor.protocol_version);
    println!("  artifact:   {}", unpacked.artifact_path.display());
    if let Some(sig) = unpacked.signature_path {
        println!("  signature:  {}", sig.display());
    } else {
        println!("  signature:  (none — unsigned)");
    }
    if let Some(license) = unpacked.license_path {
        println!("  license:    {}", license.display());
    } else {
        println!("  license:    (none)");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// cache — manage the local OCI unpack cache
// ---------------------------------------------------------------------------

fn cmd_cache_gc(args: &[String]) -> anyhow::Result<()> {
    let mut cache_dir: Option<PathBuf> = None;
    let mut older_than_secs: Option<u64> = None;
    let mut keep_latest: usize = 3;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cache-dir" => {
                cache_dir = args
                    .get(i + 1)
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow::anyhow!("--cache-dir requires a path"))
                    .map(Some)?;
                i += 2;
            }
            "--older-than" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--older-than requires a duration"))?;
                older_than_secs = Some(parse_duration_secs(raw).ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid --older-than value '{raw}': use e.g. 30d, 12h, 2w, 3600s"
                    )
                })?);
                i += 2;
            }
            "--keep-latest" => {
                let raw = args
                    .get(i + 1)
                    .ok_or_else(|| anyhow::anyhow!("--keep-latest requires an integer"))?;
                keep_latest = raw
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid --keep-latest '{raw}': {e}"))?;
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_cache_gc_usage();
                return Ok(());
            }
            flag => {
                return Err(anyhow::anyhow!(
                    "unknown flag '{flag}' for cache gc — try --help"
                ));
            }
        }
    }

    let cache_dir = cache_dir.unwrap_or_else(resolve_default_cache_dir);

    if !cache_dir.exists() {
        println!("Cache directory does not exist: {}", cache_dir.display());
        println!("Nothing to do.");
        return Ok(());
    }

    let entries = scan_cache_dir(&cache_dir)?;
    if entries.is_empty() {
        println!("No plugin artifacts in cache: {}", cache_dir.display());
        return Ok(());
    }

    let plan = plan_gc(
        &entries,
        keep_latest,
        older_than_secs.map(std::time::Duration::from_secs),
        std::time::SystemTime::now(),
    );

    print_gc_report(&cache_dir, &plan, dry_run);

    if !dry_run {
        let (removed_count, removed_bytes, errors) = execute_removals(&plan.removed);
        println!();
        println!(
            "Removed {removed_count} file(s), freed {}.",
            format_bytes(removed_bytes)
        );
        if !errors.is_empty() {
            eprintln!();
            eprintln!("Errors:");
            for err in &errors {
                eprintln!("  {err}");
            }
            return Err(anyhow::anyhow!(
                "cache gc: {} removal error(s)",
                errors.len()
            ));
        }
    }

    Ok(())
}

fn print_cache_gc_usage() {
    eprintln!("Usage: mcpg-plugin cache gc [options]");
    eprintln!();
    eprintln!("Garbage-collect the local OCI unpack cache — walks the cache");
    eprintln!("directory, groups entries by plugin reference, keeps the N most");
    eprintln!("recent per group, and removes the rest iff they are older than");
    eprintln!("the --older-than threshold.");
    eprintln!();
    eprintln!("Defaults are deliberately conservative: without --older-than,");
    eprintln!("nothing is ever removed.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --cache-dir <path>     Cache directory to GC. Default: same");
    eprintln!("                         resolution as the gateway");
    eprintln!("                         (XDG_CACHE_HOME/mcpg/plugins/oci → ");
    eprintln!("                         $HOME/.cache/mcpg/plugins/oci →");
    eprintln!("                         /var/cache/mcpg/plugins/oci).");
    eprintln!("  --keep-latest <N>      Per plugin, keep the N most recently-used");
    eprintln!("                         entries. Default: 3.");
    eprintln!("  --older-than <dur>     Only entries older than this are eligible");
    eprintln!("                         for removal. Units: s/m/h/d/w. No default");
    eprintln!("                         (keep forever).");
    eprintln!("  --dry-run              Print the plan; do not delete anything.");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  # Preview: keep 3 latest per plugin, remove rest older than 30 days");
    eprintln!("  mcpg-plugin cache gc --older-than 30d --dry-run");
    eprintln!();
    eprintln!("  # Aggressive: keep only 1 per plugin, remove rest > 7 days old");
    eprintln!("  mcpg-plugin cache gc --keep-latest 1 --older-than 7d");
}

/// Parse a human-friendly duration like `30d`, `12h`, `3600s`, `2w`.
/// Returns seconds. Unit defaults to seconds if absent.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let num_str: String = s.chars().take_while(char::is_ascii_digit).collect();
    if num_str.is_empty() {
        return None;
    }
    let num: u64 = num_str.parse().ok()?;
    let unit: String = s.chars().skip(num_str.len()).collect();
    let multiplier = match unit.trim() {
        "" | "s" | "sec" | "secs" | "seconds" => 1,
        "m" | "min" | "mins" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        _ => return None,
    };
    num.checked_mul(multiplier)
}

fn resolve_default_cache_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("mcpg").join("plugins").join("oci");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return PathBuf::from(home)
            .join(".cache")
            .join("mcpg")
            .join("plugins")
            .join("oci");
    }
    PathBuf::from("/var/cache/mcpg/plugins/oci")
}

#[derive(Debug, Clone)]
struct CacheEntry {
    path: PathBuf,
    /// Grouping key — filename stem with trailing `_tag` stripped.
    /// Two entries for the same plugin (different versions or digests)
    /// share a group so `--keep-latest` applies per plugin, not per
    /// version.
    group: String,
    /// Tag portion (everything after the final `_` in the stem).
    /// Verified by unit tests that assert grouping extracted the right
    /// tag for each fixture; the report uses `path.file_name()`
    /// directly because that's what operators see on disk.
    #[allow(
        dead_code,
        reason = "read by scan_cache_dir tests that assert tag extraction correctness"
    )]
    tag: String,
    mtime: std::time::SystemTime,
    size: u64,
}

/// Extract `(group, tag)` from a sanitised cache filename stem.
///
/// Cache files are named by `sanitize_for_path(normalised_oci_ref)` +
/// `".zip"`, where `sanitize_for_path` replaces `/`, `:`, `@`, etc. with
/// `_`. Typical stems: `ghcr.io_mcpg-dev_plugins_audit_1.0.0` or
/// `ghcr.io_plugins_audit_sha256_abcd1234`. The tag is whatever follows
/// the last `_`.
fn split_group_tag(stem: &str) -> (String, String) {
    match stem.rsplit_once('_') {
        Some((group, tag)) if !group.is_empty() && !tag.is_empty() => {
            (group.to_owned(), tag.to_owned())
        }
        _ => (stem.to_owned(), String::new()),
    }
}

fn scan_cache_dir(dir: &std::path::Path) -> anyhow::Result<Vec<CacheEntry>> {
    let mut entries = Vec::new();
    for dir_entry in std::fs::read_dir(dir)? {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("zip") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let (group, tag) = split_group_tag(stem);
        let md = std::fs::metadata(&path)?;
        let mtime = md.modified()?;
        let size = md.len();
        entries.push(CacheEntry {
            path,
            group,
            tag,
            mtime,
            size,
        });
    }
    Ok(entries)
}

#[derive(Debug)]
struct GcPlan {
    kept: Vec<CacheEntry>,
    removed: Vec<CacheEntry>,
}

/// Decide what to remove.
///
/// Policy:
///
/// 1. Group by `CacheEntry.group`.
/// 2. Within each group, sort newest-first by mtime.
/// 3. Keep the first `keep_latest` entries unconditionally.
/// 4. For entries beyond `keep_latest`: remove iff `older_than` is Some
///    AND the entry's age (now - mtime) meets-or-exceeds the threshold.
/// 5. Otherwise, keep.
fn plan_gc(
    entries: &[CacheEntry],
    keep_latest: usize,
    older_than: Option<std::time::Duration>,
    now: std::time::SystemTime,
) -> GcPlan {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<String, Vec<CacheEntry>> = BTreeMap::new();
    for e in entries {
        groups.entry(e.group.clone()).or_default().push(e.clone());
    }

    let mut kept = Vec::new();
    let mut removed = Vec::new();

    for (_group, mut group_entries) in groups {
        group_entries.sort_by_key(|e| std::cmp::Reverse(e.mtime));
        for (idx, entry) in group_entries.into_iter().enumerate() {
            if idx < keep_latest {
                kept.push(entry);
                continue;
            }
            let eligible = match older_than {
                Some(threshold) => now
                    .duration_since(entry.mtime)
                    .map(|age| age >= threshold)
                    .unwrap_or(false),
                None => false,
            };
            if eligible {
                removed.push(entry);
            } else {
                kept.push(entry);
            }
        }
    }

    GcPlan { kept, removed }
}

fn print_gc_report(cache_dir: &std::path::Path, plan: &GcPlan, dry_run: bool) {
    println!("Cache: {}", cache_dir.display());
    println!(
        "Kept: {} file(s), Removed: {}{}",
        plan.kept.len(),
        plan.removed.len(),
        if dry_run { " (dry-run)" } else { "" }
    );
    println!();

    if !plan.removed.is_empty() {
        let label = if dry_run { "Would remove" } else { "Removing" };
        println!("{label}:");
        for entry in &plan.removed {
            println!(
                "  {:8}  {}  {}",
                format_bytes(entry.size),
                format_age(entry.mtime),
                entry.path.file_name().unwrap_or_default().to_string_lossy(),
            );
        }
    }

    if !plan.kept.is_empty() {
        println!();
        println!("Kept:");
        for entry in &plan.kept {
            println!(
                "  {:8}  {}  {}",
                format_bytes(entry.size),
                format_age(entry.mtime),
                entry.path.file_name().unwrap_or_default().to_string_lossy(),
            );
        }
    }
}

fn execute_removals(targets: &[CacheEntry]) -> (usize, u64, Vec<String>) {
    let mut removed = 0_usize;
    let mut bytes = 0_u64;
    let mut errors = Vec::new();
    for entry in targets {
        match std::fs::remove_file(&entry.path) {
            Ok(()) => {
                removed += 1;
                bytes += entry.size;
            }
            Err(e) => errors.push(format!("{}: {}", entry.path.display(), e)),
        }
    }
    (removed, bytes, errors)
}

fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if n >= GB {
        format!("{:.2}G", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.1}M", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1}K", n as f64 / KB as f64)
    } else {
        format!("{n}B")
    }
}

fn format_age(mtime: std::time::SystemTime) -> String {
    let age = std::time::SystemTime::now()
        .duration_since(mtime)
        .unwrap_or(std::time::Duration::ZERO);
    let secs = age.as_secs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

// ---------------------------------------------------------------------------
// test — load a packaged plugin and exercise its vtable contract
// ---------------------------------------------------------------------------
//
// In-process mock-gateway harness. The plugin's ZIP is unpacked to a
// tempdir, signature-verified (if a trusted key is provided; otherwise
// skipped with a banner), loaded via the native cdylib loader, and its
// vtable is invoked with a caller-supplied `PluginContext` +
// arguments. The returned decision is printed as pretty JSON so
// authors can diff against expectations in their CI.
//
// Exit codes:
//
//   0  — the vtable returned a well-formed decision (any variant). The
//        plugin respected its contract; the caller's asserting logic
//        decides whether the *specific* decision was the one they
//        wanted.
//   1  — the plugin failed to load, deserialise its config, respond
//        before the host's watchdog, or otherwise broke the ABI.
//
// This is deliberately not a full gateway; it does not compose multiple
// plugins into a chain (use `mcpg` itself with a fixture config for
// that). It's the shortest path from "I built a cdylib" to "I know the
// FFI contract holds up."

fn cmd_test(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        print_test_usage();
        return if args.is_empty() {
            Err(anyhow::anyhow!("missing <archive.zip>"))
        } else {
            Ok(())
        };
    }

    let archive = PathBuf::from(&args[0]);

    let mut descriptor_override: Option<PathBuf> = None;
    let mut context_file: Option<PathBuf> = None;
    let mut arguments_file: Option<PathBuf> = None;
    let mut config_file: Option<PathBuf> = None;
    let mut public_key: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--descriptor" => {
                descriptor_override =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--descriptor requires a path")
                    })?));
                i += 2;
            }
            "--context" => {
                context_file =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--context requires a path")
                    })?));
                i += 2;
            }
            "--arguments" => {
                arguments_file =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--arguments requires a path")
                    })?));
                i += 2;
            }
            "--config" => {
                config_file =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--config requires a path")
                    })?));
                i += 2;
            }
            "--key" => {
                public_key = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--key requires a path"))?,
                ));
                i += 2;
            }
            flag => {
                return Err(anyhow::anyhow!("unknown flag: {flag}"));
            }
        }
    }

    // Unpack the archive to an auto-cleaned tempdir. The directory
    // lives for the duration of `cmd_test`; when this function returns,
    // the `_workdir` guard drops and removes everything.
    let workdir = tempfile::tempdir().map_err(|e| anyhow::anyhow!("create tempdir: {e}"))?;
    let unpacked = mcpg_plugin_host::Package::unpack_to(&archive, workdir.path())
        .map_err(|e| anyhow::anyhow!("unpack {}: {e}", archive.display()))?;

    // Descriptor override — useful for "what-if" testing (e.g.,
    // simulate a required_capability that isn't in the shipped yaml).
    let descriptor = if let Some(ref path) = descriptor_override {
        let yaml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read --descriptor {}: {e}", path.display()))?;
        serde_yaml::from_str::<mcpg_plugin_protocol::PluginDescriptor>(&yaml)
            .map_err(|e| anyhow::anyhow!("parse --descriptor: {e}"))?
    } else {
        unpacked.descriptor.clone()
    };

    // Build context / arguments / config from the optional files or
    // fall back to defaults.
    let context = load_context(context_file.as_deref())?;
    let arguments =
        load_json_file(arguments_file.as_deref())?.unwrap_or_else(|| serde_json::json!({}));
    let config = load_json_file(config_file.as_deref())?.unwrap_or_else(|| serde_json::json!({}));

    // Build the verify options. A `--key` enables signature
    // verification against that key; without a key, signatures are
    // skipped (this is a dev harness; real deployments verify via the
    // gateway's trust config per spec §13).
    let (verify_opts, key_banner) = if let Some(ref key_path) = public_key {
        let bytes = std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("read --key {}: {e}", key_path.display()))?;
        let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "--key {}: expected 32 raw bytes, got {}",
                key_path.display(),
                bytes.len()
            )
        })?;
        (
            mcpg_plugin_host::native::NativeVerifyOptions {
                expected_sha256: None,
                trusted_public_keys: vec![key],
                policy: mcpg_plugin_host::SignaturePolicy::Enforce,
                revocation_list: None,
            },
            format!("signature verified against {}", key_path.display()),
        )
    } else {
        (
            mcpg_plugin_host::native::NativeVerifyOptions {
                expected_sha256: None,
                trusted_public_keys: vec![],
                policy: mcpg_plugin_host::SignaturePolicy::Disabled,
                revocation_list: None,
            },
            "signature verification skipped (no --key)".to_owned(),
        )
    };

    // If the zip carried a signature, rename it next to the artifact
    // so the loader's sidecar convention finds it
    // (`<artifact>.sig`). The unpack left it as `plugin.sig` at the
    // tempdir root.
    if let Some(sig) = &unpacked.signature_path {
        let target = {
            let mut p = unpacked.artifact_path.clone();
            let prior = p
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            p.set_file_name(format!("{prior}.sig"));
            p
        };
        std::fs::rename(sig, &target)
            .map_err(|e| anyhow::anyhow!("move signature next to artifact: {e}"))?;
    }

    let loaded = mcpg_plugin_host::native_loader::load_native_plugin(
        &unpacked.artifact_path,
        &verify_opts,
        mcpg_plugin_host::native_loader::FfiLimits::default(),
    )
    .map_err(|e| anyhow::anyhow!("load_native_plugin: {e}"))?;

    println!("Plugin loaded:");
    println!("  id:            {}", loaded.meta.manifest.id);
    println!("  version:       {}", loaded.meta.manifest.version);
    println!("  name:          {}", loaded.meta.manifest.name);
    println!("  protocol:      {}", loaded.meta.manifest.protocol_version);
    println!("  class:         {}", descriptor.class);
    println!("  runtime:       {}", descriptor.runtime);
    println!("  trust:         {key_banner}");
    println!();

    // Dispatch based on the descriptor class. Each arm builds the
    // matching adapter, invokes exactly one representative vtable
    // entry, pretty-prints the response, and returns.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build tokio runtime: {e}"))?;

    // Native adapters take an `alias`
    // + `Arc<dyn HostServices>`, and their constructors call
    // `HostBridge::with_services` which captures the current tokio
    // runtime — so adapter construction MUST happen inside the
    // runtime. We hand the plugin a stub services impl
    // (`NullHostServices` — host calls return typed
    // "not wired" errors) and use the descriptor id as the alias.
    let alias = descriptor.id.clone();
    let services: std::sync::Arc<dyn mcpg_plugin_host::host_services::HostServices> =
        std::sync::Arc::new(mcpg_plugin_host::host_services::NullHostServices);

    rt.block_on(async {
        match descriptor.class {
            mcpg_plugin_protocol::PluginClass::ToolGate => {
                let adapter = mcpg_plugin_host::native_loader::NativeToolGateAdapter::new(
                    loaded,
                    config.clone(),
                    alias.clone(),
                    services.clone(),
                )
                .map_err(|e| anyhow::anyhow!("NativeToolGateAdapter::new: {e}"))?;

                println!("→ evaluate_pre_dispatch");
                let decision = {
                    use mcpg_plugin_protocol::ToolGatePlugin as _;
                    adapter
                        .evaluate_pre_dispatch(&context, &arguments, None, &config)
                        .await
                };
                print_gate_decision(&decision);

                println!();
                println!("→ evaluate_post_dispatch (result=null, duration=1ms)");
                let post = {
                    use mcpg_plugin_protocol::ToolGatePlugin as _;
                    adapter
                        .evaluate_post_dispatch(
                            &context,
                            &arguments,
                            &serde_json::Value::Null,
                            1,
                            &config,
                        )
                        .await
                };
                print_gate_decision(&post);
            }
            mcpg_plugin_protocol::PluginClass::Transform => {
                let adapter = mcpg_plugin_host::native_loader::NativeTransformAdapter::new(
                    loaded,
                    config.clone(),
                    alias.clone(),
                    services.clone(),
                )
                .map_err(|e| anyhow::anyhow!("NativeTransformAdapter::new: {e}"))?;

                println!("→ transform_arguments");
                let result = {
                    use mcpg_plugin_protocol::TransformPlugin as _;
                    adapter
                        .transform_arguments(&context, &arguments, &config)
                        .await
                };
                print_transform_result(&result);
            }
            mcpg_plugin_protocol::PluginClass::IdentityProvider => {
                // v20 ABI: NativeIdentityProviderAdapter::new takes an optional
                // ClusterClientRef. The `mcpg plugin test` CLI is a
                // single-shot harness with no coordinator wired, so we
                // pass `None` — the plugin sees `make` called with
                // `RNone` cluster, just like a single-node deploy
                // without a registered coordinator.
                let adapter = mcpg_plugin_host::native_loader::NativeIdentityProviderAdapter::new(
                    loaded,
                    config.clone(),
                    alias.clone(),
                    services.clone(),
                    None,
                )
                .map_err(|e| anyhow::anyhow!("NativeIdentityProviderAdapter::new: {e}"))?;

                // Flatten PluginContext.identity.attributes + a couple of
                // synthetic headers so resolvers that key on typical
                // `Authorization` / `X-*` inputs see something to work
                // with.
                let headers = synthesise_headers(&context);

                println!("→ resolve_identity  (headers: {})", headers.len());
                let resolution = {
                    use mcpg_plugin_protocol::IdentityProviderPlugin as _;
                    let metadata = mcpg_plugin_protocol::types::RequestMetadata::default();
                    adapter.resolve_identity(&headers, &metadata, &config).await
                };
                print_identity_resolution(&resolution);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "test does not yet drive class `{other}` end-to-end — \
                     the FFI vtable for this kind isn't fleshed out yet"
                ));
            }
        }
        Ok::<(), anyhow::Error>(())
    })?;

    println!();
    println!("✓ vtable contract respected.");
    Ok(())
}

// ---------------------------------------------------------------------------
// new — scaffold a plugin crate
// ---------------------------------------------------------------------------

/// Kinds the scaffolder knows how to template. Each entry has a
/// matching template string that wires the unified `declare_plugin!`
/// macro with one entity of the chosen kind. The legacy per-kind
/// macros are gone; every kind goes through the same
/// `declare_plugin!` arm.
const SCAFFOLD_KINDS: &[&str] = &[
    "tool_gate",
    "transform",
    "identity",
    "backend",
    "audit_sink",
    "log_sink",
    "metrics_sink",
    "telemetry_sink",
    "secret_provider",
    "config_provider",
    "store",
    "cache",
    "policy_engine",
    "approval_notifier",
    "credential_issuer",
    "catalog_provider",
    "cluster",
    "transport",
    "http_route",
    "watch_strategy",
    "content_store",
];

fn cmd_new(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h" | "help") {
        print_new_usage();
        return if args.is_empty() {
            Err(anyhow::anyhow!("missing arguments — see usage above"))
        } else {
            Ok(())
        };
    }

    let mut kind: Option<String> = None;
    let mut name: Option<String> = None;
    let mut id: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kind" => {
                kind = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--kind requires a value"))?
                        .to_owned(),
                );
                i += 2;
            }
            "--name" => {
                name = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--name requires a value"))?
                        .to_owned(),
                );
                i += 2;
            }
            "--id" => {
                id = Some(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .to_owned(),
                );
                i += 2;
            }
            "--out" => {
                out_dir = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--out requires a path"))?,
                ));
                i += 2;
            }
            flag => {
                return Err(anyhow::anyhow!("unknown flag: {flag}"));
            }
        }
    }

    let kind = kind.ok_or_else(|| anyhow::anyhow!("--kind is required"))?;
    let name = name.ok_or_else(|| anyhow::anyhow!("--name is required"))?;
    if !SCAFFOLD_KINDS.iter().any(|k| *k == kind) {
        return Err(anyhow::anyhow!(
            "unknown kind '{}'. Supported: {}",
            kind,
            SCAFFOLD_KINDS.join(", ")
        ));
    }
    // Plugin id format: `dev.<scope>.<kind>.<name>`. Operator
    // can override at scaffold time via `--id`.
    let plugin_id = id.unwrap_or_else(|| format!("dev.example.{}.{}", kind, name));
    // Crate name: `mcpg-plugin-<kind>-<name>`. Hyphenated form
    // is the cargo idiom; the in-source `mod` path uses
    // underscores via `module_path!()`.
    let crate_name = format!("mcpg-plugin-{}-{}", kind.replace('_', "-"), name);
    let dir = out_dir.unwrap_or_else(|| PathBuf::from(&crate_name));

    if dir.exists() {
        return Err(anyhow::anyhow!(
            "target directory already exists: {}. Pass a different `--out` or remove it first.",
            dir.display()
        ));
    }

    scaffold_plugin_crate(&dir, &kind, &name, &plugin_id, &crate_name)?;

    println!("✓ Created plugin scaffold at {}", dir.display());
    println!();
    println!("Layout:");
    println!("  {}/", dir.display());
    println!("    Cargo.toml        ({} cdylib + rlib)", crate_name);
    println!("    plugin.yaml       (descriptor — cross-checked at registration)");
    println!("    src/lib.rs        (declare_plugin! invocation + stub trait impl)");
    println!("    README.md         (build + test instructions)");
    println!();
    println!("Next steps:");
    println!("  cd {}", dir.display());
    println!("  cargo build --release");
    println!(
        "  mcpg plugin test target/release/lib{}.so",
        crate_name.replace('-', "_")
    );
    println!();
    println!("Plugin id: {plugin_id}");
    println!("Kind:      {kind}");
    Ok(())
}

fn scaffold_plugin_crate(
    dir: &Path,
    kind: &str,
    inner_name: &str,
    plugin_id: &str,
    crate_name: &str,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir.join("src"))
        .map_err(|e| anyhow::anyhow!("create_dir_all {}/src: {e}", dir.display()))?;
    std::fs::write(dir.join("Cargo.toml"), render_cargo_toml(crate_name, kind))?;
    std::fs::write(
        dir.join("plugin.yaml"),
        render_plugin_yaml(plugin_id, kind, inner_name),
    )?;
    std::fs::write(
        dir.join("src").join("lib.rs"),
        render_lib_rs(kind, inner_name, plugin_id),
    )?;
    std::fs::write(
        dir.join("README.md"),
        render_readme(crate_name, kind, inner_name, plugin_id),
    )?;
    Ok(())
}

fn render_cargo_toml(crate_name: &str, _kind: &str) -> String {
    // The scaffolded crate ships both crate-type entries so a
    // single source supports both cdylib OCI distribution AND
    // static-firstparty embedding into a custom gateway binary.
    // Feature flags follow `libs/plugin-sdk` conventions:
    // `cdylib-export` toggles the `#[no_mangle]` symbol on the
    // cdylib path; `static-firstparty` pulls in `mcpg-plugin-host`
    // so the macro's `register_static()` expansion compiles.
    format!(
        r#"[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
default = ["cdylib-export"]
# Emit the `mcpg_plugin_register` extern "C" symbol — the
# macro-generated cdylib entry point the host's dynamic loader
# looks up at OCI load time. Disable when embedding statically.
cdylib-export = ["mcpg-plugin-sdk/cdylib-export"]
# Pull in `mcpg-plugin-host` + `anyhow` so the macro's
# `register_static()` expansion compiles. Operators embedding
# the plugin into a custom gateway binary enable this.
static-firstparty = ["mcpg-plugin-sdk/static-firstparty"]

[dependencies]
mcpg-plugin-protocol = "1"
mcpg-plugin-sdk = "1"
serde_json = "1"
"#
    )
}

fn render_plugin_yaml(plugin_id: &str, kind: &str, _inner_name: &str) -> String {
    // Required-capabilities is intentionally empty — most starter
    // plugins don't need any. Authors add what they need: see
    // `mcpg_plugin_protocol::capability::Capability::known_names()`.
    format!(
        r#"schema: mcpg.dev/plugin/v1
id: {plugin_id}
name: {plugin_id}
description: Scaffolded by `mcpg plugin new` — replace this with a real description.
class: {kind}
runtime: native-cdylib-v1
protocol_version: '1.22'
required_capabilities: []
"#
    )
}

fn render_lib_rs(kind: &str, inner_name: &str, plugin_id: &str) -> String {
    // `tool_gate` gets a fully-fleshed-out unified-macro template
    // with a working trait impl + capabilities slot. Other kinds
    // get a stub scaffold pointing at the same unified
    // `declare_plugin!` entry point — the per-kind legacy macros
    // are gone, so every kind funnels through one macro now.
    if kind == "tool_gate" {
        render_lib_rs_tool_gate(inner_name, plugin_id)
    } else {
        render_lib_rs_per_kind(kind, plugin_id)
    }
}

fn render_lib_rs_tool_gate(inner_name: &str, plugin_id: &str) -> String {
    let mod_ident = inner_name.replace('-', "_");
    format!(
        r#"//! Scaffolded by `mcpg plugin new --kind tool_gate`.
//!
//! Authored via the unified [`declare_plugin!`](mcpg_plugin_sdk::declare_plugin)
//! macro. One invocation generates BOTH the
//! cdylib `mcpg_plugin_register()` export AND a `register_static()`
//! function for the static-firstparty path — same source, two
//! integration points.

use mcpg_plugin_protocol::manifest::{{PluginClass, PluginManifest}};
use mcpg_plugin_protocol::types::{{GateDecision, PluginContext}};
use mcpg_plugin_protocol::PROTOCOL_VERSION;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;

pub struct MyGate {{
    manifest: PluginManifest,
}}

impl MyGate {{
    pub fn new(_config_json: &str) -> Self {{
        Self {{ manifest: build_manifest() }}
    }}
}}

fn build_manifest() -> PluginManifest {{
    PluginManifest {{
        license: None,
        id: "{plugin_id}".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        name: "{plugin_id}".into(),
        plugin_class: PluginClass::ToolGate,
        protocol_version: PROTOCOL_VERSION.into(),
        required_capabilities: vec![],
        tags: vec![],
        provides: vec![],
        provides_schemes: vec![],
        module_path_prefix: ::std::module_path!()
            .split("::")
            .next()
            .unwrap_or("plugin")
            .to_owned(),
        backend_profile: None,
    }}
}}

impl SyncToolGate for MyGate {{
    fn manifest(&self) -> &PluginManifest {{
        license: None,
        &self.manifest
    }}

    fn evaluate_pre(
        &self,
        _ctx: &PluginContext,
        _args: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {{
        // TODO: implement your pre-dispatch logic.
        GateDecision::allow()
    }}

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _args: &serde_json::Value,
        _result: &serde_json::Value,
        _duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {{
        // TODO: implement your post-dispatch logic.
        GateDecision::allow()
    }}
}}

declare_plugin! {{
    plugin_id: "{plugin_id}",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    entities: [
        tool_gate as {mod_ident} {{
            inner_name: "",
            plugin_type: MyGate,
            factory: |cfg: &str| MyGate::new(cfg),
        }},
    ],
}}
"#
    )
}

fn render_lib_rs_per_kind(kind: &str, plugin_id: &str) -> String {
    // Stub scaffold for kinds where the scaffolder doesn't yet ship
    // a fully-fleshed-out template. The unified `declare_plugin!`
    // macro covers ALL 20 kinds (the legacy per-kind macros are
    // gone), so plugin authors only need to implement
    // the matching `Sync{kind_camel}` trait and invoke
    // `declare_plugin!` with one entity of this kind.
    format!(
        r#"//! Scaffolded by `mcpg plugin new --kind {kind}`.
//!
//! Authored via the unified
//! [`declare_plugin!`](mcpg_plugin_sdk::declare_plugin) macro —
//! the same entry point every kind uses.

// TODO: implement the `Sync{kind_camel}` trait from
// `mcpg_plugin_sdk::ffi` and invoke
// `mcpg_plugin_sdk::declare_plugin!` with one entity of kind
// `{kind}`. See the macro's rustdoc for the full syntax.

const PLUGIN_ID: &str = "{plugin_id}";

// Placeholder so `cargo build` succeeds on a fresh scaffold —
// replace with the real trait impl + macro invocation.
fn _unused_id() -> &'static str {{
    PLUGIN_ID
}}
"#,
        kind = kind,
        kind_camel = snake_to_camel(kind),
        plugin_id = plugin_id,
    )
}

fn snake_to_camel(s: &str) -> String {
    let mut out = String::new();
    let mut next_upper = true;
    for ch in s.chars() {
        if ch == '_' {
            next_upper = true;
        } else if next_upper {
            out.extend(ch.to_uppercase());
            next_upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn render_readme(crate_name: &str, kind: &str, _inner_name: &str, plugin_id: &str) -> String {
    let so_name = crate_name.replace('-', "_");
    format!(
        r#"# {crate_name}

Plugin scaffolded by `mcpg plugin new --kind {kind} --name <name>`.

- **Plugin id**: `{plugin_id}`
- **Class**: `{kind}`
- **Runtime**: `native-cdylib-v1`

## Build (cdylib for OCI distribution)

```sh
cargo build --release
```

The cdylib lands at `target/release/lib{so_name}.so` (Linux),
`lib{so_name}.dylib` (macOS), or `{so_name}.dll` (Windows).

## Smoke-test

```sh
mcpg plugin pack \\
    --descriptor plugin.yaml \\
    --artifact target/release/lib{so_name}.so \\
    --out {crate_name}.zip

mcpg plugin test {crate_name}.zip
```

## Static-firstparty embedding

Add the crate as a path-dep to your gateway crate with
`default-features = false, features = ["static-firstparty"]`. Then
in the gateway's boot path:

```rust,ignore
{so_name}::register_static(&mut registrar, &[], host)?;
```

The `host` argument is the `mcpg_plugin_sdk::HostHandle` the gateway
constructs from its `LateBoundHostServices` + the plugin entry's
alias.

The macro-generated `register_static()` wires the plugin through
the in-process trait dispatch, bypassing the FFI entirely, so the
fast path is preserved.
"#
    )
}

fn print_new_usage() {
    eprintln!("Usage: mcpg plugin new --kind <K> --name <N> [--id <ID>] [--out <DIR>]");
    eprintln!();
    eprintln!("Scaffold a new plugin crate under `<N>/` (or `--out <DIR>`).");
    eprintln!();
    eprintln!("Supported kinds:");
    for k in SCAFFOLD_KINDS {
        eprintln!("  {k}");
    }
    eprintln!();
    eprintln!("Defaults:");
    eprintln!("  --id <ID>     dev.example.<kind>.<name>");
    eprintln!("  --out <DIR>   ./mcpg-plugin-<kind>-<name>");
    eprintln!();
    eprintln!("All scaffolds use the unified `declare_plugin!` macro.");
    eprintln!("ToolGate scaffolds");
    eprintln!("ship a fully-fleshed-out template; other kinds get a");
    eprintln!("stub pointing at the same macro entry point.");
}

fn print_test_usage() {
    eprintln!("Usage: mcpg-plugin test <archive.zip> \\");
    eprintln!("    [--descriptor <path>]  [--context <json-file>] \\");
    eprintln!("    [--arguments <json-file>] [--config <json-file>] \\");
    eprintln!("    [--key <public-key>]");
    eprintln!();
    eprintln!("Load a packaged plugin into an in-process mock gateway, exercise its");
    eprintln!("vtable contract, and print the decision as pretty JSON. Exit 0 if the");
    eprintln!("contract was respected, 1 otherwise.");
    eprintln!();
    eprintln!("What each flag does:");
    eprintln!();
    eprintln!("  --descriptor <path>    Override the packaged plugin.yaml with one");
    eprintln!("                         on disk (what-if testing).");
    eprintln!("  --context <json>       Override PluginContext. Defaults to a single");
    eprintln!("                         verified caller; see libs/plugin-sdk/examples/");
    eprintln!("                         sample-context.json for the full schema.");
    eprintln!("  --arguments <json>     JSON passed as the tool/transform arguments.");
    eprintln!("                         Defaults to {{}}.");
    eprintln!("  --config <json>        Per-plugin operator config JSON passed as the");
    eprintln!("                         vtable `config` argument. Defaults to {{}}.");
    eprintln!("  --key <public-key>     Verify the plugin's signature against this");
    eprintln!("                         32-byte Ed25519 key. Without --key,");
    eprintln!("                         signatures are skipped (dev-only).");
    eprintln!();
    eprintln!("Dispatch is class-aware:");
    eprintln!();
    eprintln!("  tool_gate          → evaluate_pre_dispatch + evaluate_post_dispatch");
    eprintln!("  transform          → transform_arguments");
    eprintln!("  identity_provider  → resolve_identity");
    eprintln!();
    eprintln!("Binding / watch_strategy classes are accepted by the CLI but return an");
    eprintln!("error — they are not yet supported over FFI here; exercise them via");
    eprintln!("`mcpg` with a fixture config instead.");
}

fn load_context(path: Option<&Path>) -> anyhow::Result<mcpg_plugin_protocol::PluginContext> {
    match path {
        Some(p) => {
            let body = std::fs::read(p)
                .map_err(|e| anyhow::anyhow!("read --context {}: {e}", p.display()))?;
            // Tolerate both JSON and YAML; --context naturally collides
            // with both in the wild.
            let v: serde_json::Value = match p.extension().and_then(|s| s.to_str()) {
                Some("yaml") | Some("yml") => {
                    let y: serde_yaml::Value = serde_yaml::from_slice(&body)
                        .map_err(|e| anyhow::anyhow!("parse YAML --context: {e}"))?;
                    serde_json::to_value(y)
                        .map_err(|e| anyhow::anyhow!("yaml→json --context: {e}"))?
                }
                _ => serde_json::from_slice(&body)
                    .map_err(|e| anyhow::anyhow!("parse JSON --context: {e}"))?,
            };
            serde_json::from_value(v).map_err(|e| anyhow::anyhow!("--context shape: {e}"))
        }
        None => Ok(default_context()),
    }
}

fn load_json_file(path: Option<&Path>) -> anyhow::Result<Option<serde_json::Value>> {
    match path {
        Some(p) => {
            let body =
                std::fs::read(p).map_err(|e| anyhow::anyhow!("read {}: {e}", p.display()))?;
            let v: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|e| anyhow::anyhow!("parse {}: {e}", p.display()))?;
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

fn default_context() -> mcpg_plugin_protocol::PluginContext {
    mcpg_plugin_protocol::PluginContext {
        request_id: "mcpg-plugin-test".to_owned(),
        session_id: None,
        tool_name: "test.tool".to_owned(),
        surface: "tool".to_owned(),
        transport: "http".to_owned(),
        identity: mcpg_plugin_protocol::PluginIdentity {
            kind: "verified".to_owned(),
            trust_level: "verified".to_owned(),
            subject_id: Some("tester@example.com".to_owned()),
            auth_provider: Some("mcpg-plugin-test".to_owned()),
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        },
    }
}

fn synthesise_headers(ctx: &mcpg_plugin_protocol::PluginContext) -> Vec<(String, String)> {
    // Identity plugins typically key on Authorization / X-* headers.
    // We don't have real headers in a mock harness; synthesise a
    // minimal set so plugins that look at them have something
    // deterministic to work with.
    let mut h: Vec<(String, String)> = Vec::new();
    if let Some(sub) = &ctx.identity.subject_id {
        h.push(("X-Mcpg-Test-Subject".into(), sub.clone()));
    }
    if let Some(ap) = &ctx.identity.auth_provider {
        h.push(("X-Mcpg-Test-AuthProvider".into(), ap.clone()));
    }
    for (k, v) in &ctx.identity.attributes {
        h.push((format!("X-Mcpg-Attr-{k}"), v.clone()));
    }
    h
}

fn print_gate_decision(d: &mcpg_plugin_protocol::GateDecision) {
    match serde_json::to_string_pretty(d) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{:?}", d),
    }
}

fn print_transform_result(r: &mcpg_plugin_protocol::TransformResult) {
    match serde_json::to_string_pretty(r) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{:?}", r),
    }
}

fn print_identity_resolution(r: &mcpg_plugin_protocol::IdentityResolution) {
    match serde_json::to_string_pretty(r) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{:?}", r),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn entry(group: &str, tag: &str, mtime: SystemTime, size: u64) -> CacheEntry {
        CacheEntry {
            path: PathBuf::from(format!("/cache/{group}_{tag}.zip")),
            group: group.to_owned(),
            tag: tag.to_owned(),
            mtime,
            size,
        }
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("7d"), Some(604_800));
        assert_eq!(parse_duration_secs("2w"), Some(1_209_600));
        assert_eq!(parse_duration_secs("3600"), Some(3600));
        assert_eq!(parse_duration_secs("3600sec"), Some(3600));
        assert_eq!(parse_duration_secs("1 hour"), Some(3600));
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("abc"), None);
        assert_eq!(parse_duration_secs("30x"), None);
    }

    #[test]
    fn split_group_tag_splits_on_last_underscore() {
        assert_eq!(
            split_group_tag("ghcr.io_mcpg-dev_plugins_audit_1.0.0"),
            (
                "ghcr.io_mcpg-dev_plugins_audit".to_owned(),
                "1.0.0".to_owned()
            )
        );
        assert_eq!(
            split_group_tag("audit_1.0.0"),
            ("audit".to_owned(), "1.0.0".to_owned())
        );
        assert_eq!(
            split_group_tag("noversion"),
            ("noversion".to_owned(), String::new())
        );
    }

    #[test]
    fn plan_gc_without_older_than_removes_nothing() {
        let now = SystemTime::now();
        let old = now - Duration::from_secs(10_000_000);
        let entries = vec![
            entry("audit", "1.0.0", now, 100),
            entry("audit", "1.0.1", now - Duration::from_secs(3600), 110),
            entry("audit", "1.0.2", old, 105),
            entry("audit", "1.0.3", old, 102),
            entry("audit", "1.0.4", old, 104),
        ];
        let plan = plan_gc(&entries, 3, None, now);
        assert_eq!(plan.removed.len(), 0, "no --older-than → keep forever");
        assert_eq!(plan.kept.len(), 5);
    }

    #[test]
    fn plan_gc_keeps_newest_n_per_group() {
        let now = SystemTime::now();
        let older = now - Duration::from_secs(30 * 86_400);
        let entries = vec![
            entry("audit", "1.0.0", now, 100),
            entry("audit", "1.0.1", now - Duration::from_secs(3600), 110),
            entry("audit", "1.0.2", older, 105),
            entry("audit", "1.0.3", older - Duration::from_secs(1), 102),
            entry("audit", "1.0.4", older - Duration::from_secs(2), 104),
            entry("webhook", "1.0.0", now, 200),
        ];
        // Keep latest 2 per group, remove older-than-20d beyond that.
        let plan = plan_gc(&entries, 2, Some(Duration::from_secs(20 * 86_400)), now);
        assert_eq!(plan.kept.len(), 3, "2 audit kept + 1 webhook kept");
        assert_eq!(plan.removed.len(), 3, "3 old audit beyond top-2 removed");

        // Confirm the two audit kept are the two newest.
        let audit_kept_tags: Vec<_> = plan
            .kept
            .iter()
            .filter(|e| e.group == "audit")
            .map(|e| e.tag.clone())
            .collect();
        assert!(audit_kept_tags.contains(&"1.0.0".to_owned()));
        assert!(audit_kept_tags.contains(&"1.0.1".to_owned()));
    }

    #[test]
    fn plan_gc_respects_older_than_threshold() {
        let now = SystemTime::now();
        let recent = now - Duration::from_secs(5 * 86_400); // 5d old
        let ancient = now - Duration::from_secs(60 * 86_400); // 60d old
        let entries = vec![
            entry("p", "a", now, 1),
            entry("p", "b", now - Duration::from_secs(1), 1),
            entry("p", "c", recent, 1), // beyond keep_latest=2 but only 5d old
            entry("p", "d", ancient, 1), // beyond keep_latest=2 AND 60d old
        ];
        let plan = plan_gc(&entries, 2, Some(Duration::from_secs(30 * 86_400)), now);
        let removed_tags: Vec<_> = plan.removed.iter().map(|e| e.tag.clone()).collect();
        assert_eq!(removed_tags, vec!["d".to_owned()]);
        assert_eq!(plan.kept.len(), 3);
    }

    #[test]
    fn plan_gc_empty_input() {
        let plan = plan_gc(&[], 3, Some(Duration::from_secs(86_400)), SystemTime::now());
        assert_eq!(plan.kept.len(), 0);
        assert_eq!(plan.removed.len(), 0);
    }

    #[test]
    fn plan_gc_zero_keep_latest_without_older_than_still_keeps() {
        // keep_latest=0 + older_than=None → still keep-forever (the
        // --older-than gate is the actual remover).
        let now = SystemTime::now();
        let entries = vec![entry("p", "a", now, 1)];
        let plan = plan_gc(&entries, 0, None, now);
        assert_eq!(plan.kept.len(), 1);
        assert_eq!(plan.removed.len(), 0);
    }

    #[test]
    fn scan_cache_dir_filters_non_zip() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("audit_1.0.0.zip"), b"zip").unwrap();
        std::fs::write(dir.path().join("audit_1.0.0.zip.sig"), b"sig").unwrap();
        std::fs::write(dir.path().join("not-a-plugin.txt"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let entries = scan_cache_dir(dir.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, "audit");
        assert_eq!(entries[0].tag, "1.0.0");
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(42), "42B");
        assert_eq!(format_bytes(2048), "2.0K");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0M");
        assert_eq!(format_bytes(4 * 1024 * 1024 * 1024), "4.00G");
    }

    #[test]
    fn execute_removals_reports_errors_for_missing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("audit_1.0.0.zip");
        std::fs::write(&present, b"x").unwrap();
        let missing = dir.path().join("audit_1.0.1.zip"); // never written

        let now = SystemTime::now();
        let entries = vec![
            CacheEntry {
                path: present.clone(),
                group: "audit".into(),
                tag: "1.0.0".into(),
                mtime: now,
                size: 1,
            },
            CacheEntry {
                path: missing,
                group: "audit".into(),
                tag: "1.0.1".into(),
                mtime: now,
                size: 2,
            },
        ];

        let (removed, bytes, errors) = execute_removals(&entries);
        assert_eq!(removed, 1, "one file actually removed");
        assert_eq!(bytes, 1);
        assert_eq!(errors.len(), 1, "missing file reports an error");
        assert!(!present.exists(), "present file was removed");
    }
}

// ---------------------------------------------------------------------------
// test harness — unit tests for `cmd_test`'s pure helpers
//
// The `cmd_test` flow end-to-end requires a built cdylib, which is out
// of scope for unit-level coverage; that path is exercised as an
// integration test in libs/plugin-host/tests/hello_native_roundtrip.rs
// and end-to-end via tools/verify-native-plugin-oci-e2e.sh. Here we
// cover the small pure functions that build context/arguments/headers.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod test_subcommand_tests {
    use super::*;

    #[test]
    fn default_context_is_verified_tester() {
        let ctx = default_context();
        assert_eq!(ctx.identity.kind, "verified");
        assert_eq!(ctx.identity.trust_level, "verified");
        assert_eq!(ctx.tool_name, "test.tool");
        assert_eq!(ctx.transport, "http");
        assert!(ctx.identity.subject_id.is_some());
    }

    #[test]
    fn load_context_reads_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctx.json");
        std::fs::write(
            &path,
            r#"{
                "request_id": "req-1",
                "session_id": "sess-1",
                "tool_name": "charge",
                "surface": "tool",
                "transport": "stdio",
                "identity": {
                    "kind": "verified",
                    "trust_level": "verified",
                    "subject_id": "alice",
                    "roles": ["admin"],
                    "groups": [],
                    "scopes": [],
                    "attributes": {}
                }
            }"#,
        )
        .unwrap();
        let ctx = load_context(Some(&path)).unwrap();
        assert_eq!(ctx.request_id, "req-1");
        assert_eq!(ctx.tool_name, "charge");
        assert_eq!(ctx.identity.roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn load_context_reads_yaml_file_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctx.yaml");
        let yaml = "\
request_id: req-2
session_id: null
tool_name: ping
surface: tool
transport: http
identity:
  kind: anonymous
  trust_level: unauthenticated
  subject_id: null
  roles: []
  groups: []
  scopes: []
  attributes: {}
";
        std::fs::write(&path, yaml).unwrap();
        let ctx = load_context(Some(&path)).unwrap();
        assert_eq!(ctx.request_id, "req-2");
        assert_eq!(ctx.tool_name, "ping");
        assert_eq!(ctx.identity.kind, "anonymous");
    }

    #[test]
    fn load_context_defaults_when_path_none() {
        let ctx = load_context(None).unwrap();
        assert_eq!(ctx.tool_name, "test.tool");
    }

    #[test]
    fn load_context_surfaces_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "{ not json }").unwrap();
        let err = load_context(Some(&path)).unwrap_err();
        assert!(err.to_string().contains("--context"), "got: {err}");
    }

    #[test]
    fn load_json_file_none_on_missing_path_arg() {
        assert!(load_json_file(None).unwrap().is_none());
    }

    #[test]
    fn load_json_file_parses_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("args.json");
        std::fs::write(&path, r#"{"k": 1, "items": ["a", "b"]}"#).unwrap();
        let v = load_json_file(Some(&path)).unwrap().unwrap();
        assert_eq!(v["k"], 1);
        assert_eq!(v["items"][0], "a");
    }

    #[test]
    fn synthesise_headers_exposes_identity_fields() {
        let mut ctx = default_context();
        ctx.identity
            .attributes
            .insert("tenant_id".into(), "acme".into());
        let headers = synthesise_headers(&ctx);
        // Subject + auth_provider headers plus one per attribute.
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.iter().any(|n| n == &"X-Mcpg-Test-Subject"));
        assert!(names.iter().any(|n| n == &"X-Mcpg-Test-AuthProvider"));
        assert!(names.iter().any(|n| n == &"X-Mcpg-Attr-tenant_id"));
    }

    #[test]
    fn sample_context_in_sdk_examples_parses_as_plugin_context() {
        // The file at libs/plugin-sdk/examples/sample-context.json is
        // what the docs point plugin authors at as a starting
        // fixture. It MUST deserialise cleanly into a PluginContext,
        // otherwise operators copying it will hit a cryptic parse
        // error instead of a working harness.
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .canonicalize()
            .expect("canonicalize workspace");
        let path = workspace
            .join("libs")
            .join("plugin-sdk")
            .join("examples")
            .join("sample-context.json");
        if !path.exists() {
            // The SDK's example tree is a sibling crate; a standalone
            // checkout of this crate does not carry it.
            eprintln!("skipped: {} not present in this checkout", path.display());
            return;
        }
        let ctx = load_context(Some(&path)).unwrap_or_else(|e| panic!("parse sample context: {e}"));
        assert!(!ctx.tool_name.is_empty());
        assert!(
            ctx.identity.trust_level == "verified" || ctx.identity.trust_level == "header_asserted"
        );
    }
}

#[cfg(test)]
mod sign_tests {
    //! Unit tests for the `mcpg-plugin sign` subcommand.
    //!
    //! Local-mode signing was already covered indirectly by the
    //! existing release-pipeline integration tests; the
    //! subprocess-mode path is new in v0.4 and exercised here so
    //! the CLI's contract with operator-supplied KMS scripts is
    //! locked: 64-byte stdout, no trailing newline, mandatory
    //! `--public-key`, sign-time cross-verification.
    use super::*;

    fn write_sample_artifact() -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"plugin-bytes-go-here").unwrap();
        f
    }

    /// Generate a fresh Ed25519 keypair, sign the given artifact
    /// locally, return (signature_bytes, public_key_hex).
    fn local_sign(artifact_path: &Path) -> (Vec<u8>, String) {
        // Deterministic seed for the test — easier than wiring rand.
        let seed = [42u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let bytes = std::fs::read(artifact_path).unwrap();
        use ed25519_dalek::Signer;
        let sig = signing.sign(&bytes);
        (
            sig.to_bytes().to_vec(),
            hex::encode(signing.verifying_key().as_bytes()),
        )
    }

    #[test]
    fn parse_sign_args_local_only() {
        let args = vec![
            "--key".into(),
            "/path/to/seed".into(),
            "/path/to/artifact".into(),
        ];
        let parsed = parse_sign_args(&args).unwrap();
        match parsed.signer {
            SignerKind::Local { key_path } => {
                assert_eq!(key_path, PathBuf::from("/path/to/seed"));
            }
            other => panic!("expected Local, got {other:?}"),
        }
        assert_eq!(parsed.artifact, PathBuf::from("/path/to/artifact"));
    }

    #[test]
    fn parse_sign_args_subprocess_with_public_key() {
        let args = vec![
            "--subprocess".into(),
            "/path/to/kms-signer.sh".into(),
            "--public-key".into(),
            "deadbeef".repeat(8),
            "/path/to/artifact".into(),
        ];
        let parsed = parse_sign_args(&args).unwrap();
        match parsed.signer {
            SignerKind::Subprocess {
                command,
                public_key,
            } => {
                assert_eq!(command, "/path/to/kms-signer.sh");
                assert_eq!(public_key.as_deref(), Some("deadbeef".repeat(8).as_str()));
            }
            other => panic!("expected Subprocess, got {other:?}"),
        }
    }

    #[test]
    fn parse_sign_args_rejects_both_key_and_subprocess() {
        let args = vec![
            "--key".into(),
            "/seed".into(),
            "--subprocess".into(),
            "cmd".into(),
            "/artifact".into(),
        ];
        let err = parse_sign_args(&args).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn parse_sign_args_rejects_neither() {
        let args = vec!["/artifact".into()];
        let err = parse_sign_args(&args).unwrap_err().to_string();
        assert!(
            err.contains("--key") && err.contains("--subprocess"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_sign_args_rejects_public_key_with_local() {
        let args = vec![
            "--key".into(),
            "/seed".into(),
            "--public-key".into(),
            "deadbeef".repeat(8),
            "/artifact".into(),
        ];
        let err = parse_sign_args(&args).unwrap_err().to_string();
        assert!(err.contains("only applies to --subprocess"), "got: {err}");
    }

    #[test]
    fn resolve_public_key_accepts_bare_hex() {
        let hex = "0123456789abcdef".repeat(4);
        let resolved = resolve_public_key(&hex).unwrap();
        assert_eq!(resolved, hex);
    }

    #[test]
    fn resolve_public_key_accepts_0x_prefix_uppercase() {
        let resolved = resolve_public_key(&format!("0x{}", "AB".repeat(32))).unwrap();
        assert_eq!(resolved, "ab".repeat(32));
    }

    #[test]
    fn resolve_public_key_rejects_short_hex() {
        let err = resolve_public_key("deadbeef").unwrap_err().to_string();
        assert!(err.contains("64 hex chars"), "got: {err}");
    }

    #[test]
    fn resolve_public_key_reads_file_raw_bytes() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let raw = vec![0xABu8; 32];
        std::fs::write(f.path(), &raw).unwrap();
        let resolved = resolve_public_key(&format!("file:{}", f.path().display())).unwrap();
        assert_eq!(resolved, "ab".repeat(32));
    }

    #[test]
    fn resolve_public_key_reads_file_hex_with_trailing_newline() {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), format!("{}\n", "cd".repeat(32))).unwrap();
        let resolved = resolve_public_key(&format!("file:{}", f.path().display())).unwrap();
        assert_eq!(resolved, "cd".repeat(32));
    }

    #[test]
    fn sign_subprocess_happy_path_via_inline_dd() {
        // Pre-compute the local Ed25519 signature for our artifact,
        // base64-encode it, and have the "subprocess signer" be a
        // pure-shell script that decodes + emits exactly 64 raw
        // bytes on stdout. This proves the subprocess path
        // round-trips a real signature without needing a real KMS.
        let artifact = write_sample_artifact();
        let (sig_bytes, pubkey_hex) = local_sign(artifact.path());
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let sig_b64 = B64.encode(&sig_bytes);

        // The subprocess writes exactly 64 raw bytes — no trailing
        // newline, no formatting. `printf '%s'` guarantees no
        // newline; `base64 -d` decodes to 64 raw bytes.
        let cmd = format!("printf '%s' '{sig_b64}' | base64 -d");
        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let (got_sig, got_pubkey) =
            sign_subprocess(&cmd, artifact.path(), &artifact_data, Some(&pubkey_hex)).unwrap();
        assert_eq!(got_sig, sig_bytes);
        assert_eq!(got_pubkey, pubkey_hex);
    }

    #[test]
    fn sign_subprocess_rejects_wrong_signature_size() {
        // Subprocess emits 65 bytes — the CLI catches the size
        // mismatch before trying to verify. Use `head -c` against
        // /dev/zero for portable byte-count emission (avoids bash-
        // only `{1..N}` brace expansion).
        let artifact = write_sample_artifact();
        let cmd = "head -c 65 /dev/zero".to_owned();
        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let pubkey = hex::encode([0u8; 32]); // doesn't matter
        let err = sign_subprocess(&cmd, artifact.path(), &artifact_data, Some(&pubkey))
            .unwrap_err()
            .to_string();
        assert!(err.contains("64 bytes"), "got: {err}");
    }

    #[test]
    fn sign_subprocess_rejects_wrong_public_key() {
        // Subprocess emits a real signature; declared public key
        // doesn't correspond. CLI rejects at sign time so KMS
        // misconfig surfaces immediately.
        let artifact = write_sample_artifact();
        let (sig_bytes, _pubkey_hex) = local_sign(artifact.path());
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let sig_b64 = B64.encode(&sig_bytes);
        let cmd = format!("printf '%s' '{sig_b64}' | base64 -d");

        // Wrong pubkey — fresh keypair unrelated to the signing seed.
        let other_seed = [99u8; 32];
        let other = ed25519_dalek::SigningKey::from_bytes(&other_seed);
        let other_pubkey_hex = hex::encode(other.verifying_key().as_bytes());

        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let err = sign_subprocess(
            &cmd,
            artifact.path(),
            &artifact_data,
            Some(&other_pubkey_hex),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("does NOT verify"),
            "expected verification failure, got: {err}"
        );
    }

    #[test]
    fn sign_subprocess_requires_public_key() {
        // Without --public-key, the CLI refuses to write a
        // signature it can't cross-verify. The subprocess must
        // emit exactly 64 bytes so the size check passes and the
        // public-key check is the assertion that fires.
        let artifact = write_sample_artifact();
        let cmd = "head -c 64 /dev/zero".to_owned();
        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let err = sign_subprocess(&cmd, artifact.path(), &artifact_data, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--public-key"), "got: {err}");
    }

    #[test]
    fn sign_subprocess_propagates_subprocess_failure() {
        // Subprocess exits non-zero — the CLI reports the failure
        // rather than papering over it.
        let artifact = write_sample_artifact();
        let cmd = "exit 17".to_owned();
        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let pubkey = hex::encode([0u8; 32]);
        let err = sign_subprocess(&cmd, artifact.path(), &artifact_data, Some(&pubkey))
            .unwrap_err()
            .to_string();
        assert!(err.contains("status"), "got: {err}");
    }

    #[test]
    fn sign_subprocess_passes_artifact_path_via_env() {
        // Operators key their KMS signer off the `MCPG_SIGN_ARTIFACT`
        // env var. Verify it's set to the absolute artifact path.
        let artifact = write_sample_artifact();
        let (sig_bytes, pubkey_hex) = local_sign(artifact.path());
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let sig_b64 = B64.encode(&sig_bytes);
        // Read the artifact path from MCPG_SIGN_ARTIFACT, sha256
        // it (just to USE the variable), then emit the sig. This
        // proves the subprocess sees the artifact path.
        let cmd = format!(
            "test -n \"$MCPG_SIGN_ARTIFACT\" && \
             sha256sum \"$MCPG_SIGN_ARTIFACT\" >/dev/null && \
             printf '%s' '{sig_b64}' | base64 -d"
        );
        let artifact_data = std::fs::read(artifact.path()).unwrap();
        let _ = sign_subprocess(&cmd, artifact.path(), &artifact_data, Some(&pubkey_hex)).unwrap();
    }
}
