use std::io::Write as _;
use std::path::Path;
use std::process::Command;

fn main() {
    emit_build_identity();

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

fn emit_build_identity() {
    println!("cargo:rerun-if-env-changed=PHYSARUM_GIT_SHA");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=PHYSARUM_BUILD_ID");
    println!("cargo:rerun-if-env-changed=GITHUB_RUN_ID");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");

    let git_sha = std::env::var("PHYSARUM_GIT_SHA")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_SHA")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(git_head_sha)
        .unwrap_or_else(|| "unknown".to_string());
    let git_revision = short_git_revision(&git_sha);

    let build_id = std::env::var("PHYSARUM_BUILD_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_RUN_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!("github-{value}"))
        })
        .unwrap_or_else(|| "dev".to_string());

    println!("cargo:rustc-env=PHYSARUM_GIT_SHA7={git_revision}");
    println!("cargo:rustc-env=PHYSARUM_BUILD_ID_VALUE={build_id}");
}

fn short_git_revision(value: &str) -> String {
    let value = value.trim();
    let dirty = value.ends_with("-dirty");
    let sha = value.strip_suffix("-dirty").unwrap_or(value);
    let short: String = sha.chars().take(7).collect();

    if dirty {
        format!("{short}-dirty")
    } else {
        short
    }
}

fn git_head_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;

    let sha = output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())?;

    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|status| status.status.success())
        .is_some_and(|status| !status.stdout.is_empty());

    Some(if dirty { format!("{sha}-dirty") } else { sha })
}
