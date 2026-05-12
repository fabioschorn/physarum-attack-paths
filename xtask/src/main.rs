mod build_ebpf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("build-ebpf") => build_ebpf::run(&args[2..]),
        cmd => {
            eprintln!(
                "unknown command: {}\n\nUsage:\n  cargo xtask build-ebpf [--release]",
                cmd.unwrap_or("<none>")
            );
            std::process::exit(1);
        }
    }
}
