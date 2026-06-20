pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_SHA7: &str = env!("PHYSARUM_GIT_SHA7");
pub const BUILD_ID: &str = env!("PHYSARUM_BUILD_ID_VALUE");
pub const POLICY: &str = "lab-only";

pub fn rich_version() -> String {
    format_build_identity(VERSION, GIT_SHA7, BUILD_ID, POLICY)
}

fn format_build_identity(version: &str, commit: &str, build_id: &str, policy: &str) -> String {
    format!(
        "physarum-maze v{version}\n  commit:   {commit}\n  build-id: {build_id}\n  policy:   {policy}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_version_has_stable_operator_facing_shape() {
        let output = format_build_identity("0.5.5", "abc1234", "ci-42", "lab-only");

        assert_eq!(
            output,
            "physarum-maze v0.5.5\n  commit:   abc1234\n  build-id: ci-42\n  policy:   lab-only"
        );
    }

    #[test]
    fn compiled_identity_has_expected_defaults_and_lengths() {
        assert!(
            GIT_SHA7 == "unknown"
                || GIT_SHA7.chars().count() == 7
                || (GIT_SHA7.ends_with("-dirty") && GIT_SHA7.chars().count() == 13)
        );
        assert_eq!(POLICY, "lab-only");
    }
}
