mod build_ebpf;
mod build_ebpf_packet;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("build-ebpf") => build_ebpf::run(&args[2..]),
        Some("build-ebpf-packet") => build_ebpf_packet::run(&args[2..]),
        cmd => {
            eprintln!(
                "unknown command: {}\n\nUsage:\n  cargo xtask build-ebpf [--release]\n  cargo xtask build-ebpf-packet [--release]",
                cmd.unwrap_or("<none>")
            );
            std::process::exit(1);
        }
    }
}
