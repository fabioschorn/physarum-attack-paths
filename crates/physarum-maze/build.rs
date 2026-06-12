use std::io::Write as _;
use std::path::Path;

fn main() {
    let csv_src = Path::new("data/files_exploits_rce.csv");
    let zst_dst = Path::new("data/files_exploits_rce.csv.zst");

    println!("cargo:rerun-if-changed=data/files_exploits_rce.csv");

    let csv_bytes = std::fs::read(csv_src)
        .expect("data/files_exploits_rce.csv not found — place the filtered Exploit-DB CSV there before building");

    let compressed = zstd::encode_all(csv_bytes.as_slice(), 19)
        .expect("zstd compression of Exploit-DB CSV failed");

    let mut out =
        std::fs::File::create(zst_dst).expect("could not create data/files_exploits_rce.csv.zst");
    out.write_all(&compressed)
        .expect("could not write compressed Exploit-DB CSV");
}
