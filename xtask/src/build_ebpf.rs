use std::process::{Command, ExitCode};

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

    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
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
        "building eBPF bytecode ({profile}): target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf"
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
        "eBPF bytecode ready at: target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf\n\
         run the observer with:\n  \
         sudo physarum-ebpf-observer \\\n    \
           --agent-id <id> \\\n    \
           --bpf-bytecode target/{BPF_TARGET}/{profile}/physarum-ebpf-observer-ebpf"
    );
}
