use std::process::Command;

const EBF_MANIFEST: &str = "crates/physarum-ebpf-observer-ebpf/Cargo.toml";
const BPF_TARGET: &str = "bpfel-unknown-none";

/// Build the eBPF program crate with the correct target and nightly unstable flags.
///
/// The compiled ELF ends up at:
///   target/bpfel-unknown-none/debug/physarum-ebpf-observer-ebpf   (debug)
///   target/bpfel-unknown-none/release/physarum-ebpf-observer-ebpf (release)
///
/// Pass that path to the observer binary via --bpf-bytecode.
pub fn run(args: &[String]) {
    let release = args.contains(&"--release".to_string());

    // Use `rustup run nightly cargo` so the correct toolchain is selected
    // regardless of whether `cargo` on PATH is the rustup shim or a system
    // binary (e.g. Homebrew) that does not understand the `+toolchain` flag.
    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--manifest-path",
        EBF_MANIFEST,
        "--target",
        BPF_TARGET,
        "-Z",
        "build-std=core",
    ]);
    if release {
        cmd.arg("--release");
    }

    let profile = if release { "release" } else { "debug" };
    eprintln!(
        "building eBPF bytecode ({profile}): crates/physarum-ebpf-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf"
    );

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to spawn cargo: {e}");
        std::process::exit(1);
    });

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(status.code().unwrap_or(1));
    }

    eprintln!(
        "eBPF bytecode ready at: crates/physarum-ebpf-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf\n\
         run the observer with:\n  \
         sudo physarum-ebpf-observer \\\n    \
           --agent-id <id> \\\n    \
           --bpf-bytecode crates/physarum-ebpf-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf"
    );
}
