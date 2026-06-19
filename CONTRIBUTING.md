# Contributing to CPoE

Thank you for your interest in contributing to CPoE! This document provides
guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold this code.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Use issue templates when available
- Include reproduction steps, expected vs actual behavior
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

### Development Setup

1. **Prerequisites**
   - Rust 1.75 or later (stable toolchain)
   - Cargo (included with Rust)
   - Pre-commit (recommended)
   - System dependencies (e.g., OpenSSL headers, `tpm2-tss-dev` on Linux)

2. **Clone and Setup**
   ```bash
   git clone https://github.com/writerslogic/writersproof-cli.git
   cd writerslogic
   ```

3. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

4. **Run Tests**
   ```bash
   cargo test --all-features
   ```

### Making Changes

1. **Create a Feature Branch**
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Follow Commit Conventions**
   ```
   feat(scope): add new feature
   fix(scope): fix bug description
   docs(scope): update documentation
   refactor(scope): code refactoring
   test(scope): add or update tests
   ```

3. **Write Tests**
   - Aim for high coverage on new code
   - Include unit and integration tests
   - Test edge cases and error conditions

4. **Run All Checks**
   ```bash
   cargo fmt --all -- --check  # Check formatting
   cargo clippy --all-targets --all-features -- -D warnings  # Linting
   cargo test --all-features   # Run all tests
   ```

5. **Submit Pull Request**
   - Fill out PR template completely
   - Link related issues
   - Ensure CI passes

### Code Style

- Follow standard Rust conventions (`rustfmt`, idiomatic Rust)
- Use meaningful names for variables and functions
- Document exported functions and types with doc comments (`///`)
- Keep functions focused and reasonably sized

### Cryptographic Code Guidelines

Extra care is required for cryptographic code:

1. **No Custom Primitives:** Use established crates like `sha2`, `ed25519-dalek`, `hmac`.
2. **Document Assumptions:** Security assumptions and threat models
3. **Constant-Time Operations:** Use constant-time comparison crates/functions for secrets
4. **Review Required:** Crypto changes require security-experienced maintainer review

### Documentation

- Update README.md for user-facing changes
- Update inline docs for API changes
- Add examples for new features
- Keep [specs](https://github.com/writerslogic/cpoe-docs) in sync with implementation

## Pull Request Process

1. PRs require at least one maintainer approval
2. All CI checks must pass
3. Squash commits when merging
4. Delete branch after merge

## Release Process

Releases are managed by maintainers:
- Semantic versioning (MAJOR.MINOR.PATCH)
- Github Actions / `cargo-dist` for builds
- SLSA provenance for supply chain security
- SBOM generation for compliance

## Getting Help

- [GitHub Discussions](https://github.com/writerslogic/writersproof-cli/discussions)
- Documentation in [writerslogic-docs](https://github.com/writerslogic/cpoe-docs)
- Test files for usage examples

## License and Contributor Agreement

By contributing to CPoE, you agree that:

1. **License Grant:** Your contributions will be licensed under the Apache
   License 2.0, the same license as the project.

2. **Patent Grant:** You grant Writerslogic Inc. a perpetual, worldwide,
   royalty-free license to use any patent claims you may have that are
   necessarily infringed by your contribution.

3. **Originality:** Your contributions are your original work and you have
   the right to grant these licenses.

4. **Patent Notice:** This project is the subject of USPTO Patent Application
   No. 19/460,364. See the LICENSE file for complete terms.

For questions about the contributor agreement, contact: admin@writerslogic.com
