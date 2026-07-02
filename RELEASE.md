# Release Policy and Build Verification

This document explains how project releases are produced, how to identify a
`physarum-maze` binary, and which guarantees apply to official and modified
builds.

`physarum-attack-paths` is a research prototype intended only for owned,
isolated, and authorized lab environments. An official release does not make
the software suitable for production or unauthorized targets.

## Official builds

An official build is an artifact that:

- is associated with a version tag such as `v0.5.6`;
- was built and published by the repository's GitHub Actions release workflow;
- is available from the official
  [GitHub Releases page](https://github.com/fabioschorn/physarum-attack-paths/releases);
- was built from the locked Rust dependency set and passed the release
  workflow's build and test steps;
- identifies the `lab-only` policy in `physarum-maze --version`.

The release workflow currently publishes Linux x86-64 archives. The
musl-linked `physarum-maze` archive is the portable static build used by the
propagation labs.

The only policy profile accepted by the official `physarum-maze` source is
`lab-only`. It applies the `PolicyGate` before LLM-assisted execution, including
target CIDR, confidence, method, artifact, attempt-limit, and explicit exploit
enablement checks. This remains a safety boundary for a controlled lab, not a
production security guarantee.

## Modified builds

A modified build is any binary built locally, by a fork, from an untagged
revision, or after source changes. Its version text may resemble an official
build, but it is not covered by this release policy.

The operator of a modified build is responsible for reviewing its source,
build inputs, policy behavior, and permitted environment. In particular, a
fork can change or remove the `lab-only` restrictions.

## Inspecting build identity

Run:

```bash
physarum-maze --version
```

Example:

```text
physarum-maze v0.5.6
  commit:   abc1234
  build-id: github-123456789
  policy:   lab-only
```

Interpret the fields as follows:

- `version` is the workspace version compiled into the binary.
- `commit` is the abbreviated source revision. A `-dirty` suffix indicates
  local uncommitted changes at build time; `unknown` means the revision was not
  available to the build.
- `build-id` identifies the build context. Official CI builds use a
  `github-...` identifier; local builds commonly use `dev` or `local`.
- `policy` identifies the compiled policy profile.

For an official release, compare the reported commit with the commit referenced
by the release tag. Build identity is useful provenance metadata, but is not a
cryptographic proof by itself.

## Verifying the downloaded archive

GitHub displays a SHA-256 digest for each uploaded release asset. After
downloading an archive, calculate its digest locally:

```bash
sha256sum physarum-maze-v0.5.6-x86_64-unknown-linux-musl.tar.gz
```

On macOS:

```bash
shasum -a 256 physarum-maze-v0.5.6-x86_64-unknown-linux-musl.tar.gz
```

Compare the complete result with the `sha256:` value shown for that asset on
its GitHub Release page. A matching digest confirms that the downloaded bytes
match the asset stored by GitHub.

## Current integrity limitation

Independent cryptographic signing of release artifacts is not yet implemented.
The release workflow currently does not publish a Cosign/Sigstore signature,
GPG signature, signed provenance attestation, or separately signed checksum
manifest.

The GitHub-provided SHA-256 digest provides an integrity comparison, but it
does not independently prove who authorized or produced the artifact.
Artifact signing and independently verifiable provenance remain pending release
hygiene work. Until then, download official builds only from this repository's
GitHub Releases page and verify the displayed SHA-256 digest.

## Scope and responsibility

Official and modified builds remain subject to the project's
[license](./LICENSE), [notice](./NOTICE), [security policy](./SECURITY.md), and
[research scope](./General-Docs/ROADMAP.md). Operators must use the software
only against systems they own or are explicitly authorized to test.
