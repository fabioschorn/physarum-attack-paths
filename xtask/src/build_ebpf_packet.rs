use std::process::Command;

const EBF_MANIFEST: &str = "crates/physarum-packet-observer-ebpf/Cargo.toml";
const BPF_TARGET: &str = "bpfel-unknown-none";

/// Build the ICMP tc ingress eBPF program crate.
///
/// The compiled ELF ends up at:
///   target/bpfel-unknown-none/debug/physarum-packet-observer-ebpf   (debug)
///   target/bpfel-unknown-none/release/physarum-packet-observer-ebpf (release)
///
/// Pass that path to the packet observer binary via --bpf-bytecode.
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
        "building ICMP eBPF bytecode ({profile}): \
         crates/physarum-packet-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-packet-observer-ebpf"
    );

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to spawn cargo: {e}");
        std::process::exit(1);
    });

    if !status.success() {
        eprintln!("eBPF packet observer build failed");
        std::process::exit(status.code().unwrap_or(1));
    }

    eprintln!(
        "eBPF bytecode ready at: \
         crates/physarum-packet-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-packet-observer-ebpf\n\
         run the packet observer with:\n  \
         sudo physarum-packet-observer \\\n    \
           --agent-id <id> \\\n    \
           --interface eth0 \\\n    \
           --bpf-bytecode crates/physarum-packet-observer-ebpf/target/{BPF_TARGET}/{profile}/physarum-packet-observer-ebpf"
    );
}
