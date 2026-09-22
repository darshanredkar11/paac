# Contributing to PAAC

Thank you for your interest in contributing to **PAAC (Policy-As-Access-Control)**! We welcome contributions from the open-source community.

---

## Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Development Setup

### Prerequisites
- [Rust toolchain](https://rustup.rs/) (edition 2021, MSRV 1.75+)
- Cargo toolchain

### Local Workflow

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/example/paac.git
   cd paac
   ```

2. **Run Workspace Tests**:
   ```bash
   cargo test --workspace
   ```

3. **Check Code Formatting & Linting**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   ```

4. **Run Policy Engine CLI**:
   ```bash
   cargo run -p authz-cli -- policy validate
   ```

---

## Pull Request Guidelines

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. **Include Unit & Integration Tests**: Any new feature or bugfix should include corresponding unit or integration tests in the relevant crate or integration test suite.
3. **Keep Commits Clean**: Write clear, descriptive commit messages.
4. **Submit PR**: Open a Pull Request against `main`. Ensure all CI checks pass.
