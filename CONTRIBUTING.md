# Contributing to Scilla

First off, thank you for considering contributing to Scilla!

This document provides guidelines and information about contributing to this project. Following these guidelines helps maintainers and the community understand your contribution and ensures a smooth collaboration process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Before You Start](#before-you-start)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Coding Standards](#coding-standards)
- [License](#license)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and patient with fellow contributors.

---

## Before You Start

### Check Existing Issues and PRs First

Before starting any work, **always check**:

1. **[Open Issues](../../issues)** — Someone may have already reported the bug or requested the feature.
2. **[Open Pull Requests](../../pulls)** — Someone may already be working on what you want to contribute.
3. **[Closed Issues/PRs](../../issues?q=is%3Aclosed)** — The topic may have been discussed and resolved (or intentionally declined).

**Duplicate PRs waste everyone's time.** If you find a related issue or PR, comment on it instead of creating a new one.

### Check the Project Roadmap

Scilla follows a planned development timeline. Before submitting a PR for a new feature:

1. **Review the README** — Check the status column in command tables to understand what's planned.
2. **Open an issue first** — Propose your feature and discuss implementation before writing code.
3. **Wait for maintainer approval** — Get a green light before investing significant time.

> **Note:** PRs for features that aren't on the current roadmap may be closed or marked for future consideration, even if the code is good. This isn't a rejection of your work—it's about keeping the project focused and maintainable.

---

## How Can I Contribute?

### Reporting Bugs

Great bug reports help us improve Scilla. When reporting a bug:

1. **Search existing issues** to avoid duplicates.
2. **Use the bug report template**.
3. Include:
   - A clear, descriptive title
   - Steps to reproduce the issue
   - Expected vs. actual behavior
   - Your environment (OS, Rust version, Scilla version)
   - Relevant logs or error messages

### Suggesting Features

We welcome feature suggestions! To propose a new feature:

1. **Search existing issues** to see if it's already been suggested. 
2. **Open a new issue** with:
   - A clear description of the feature
   - The problem it solves or use case it addresses
   - Any implementation ideas you have
3. **Wait for discussion** before implementing.

### Submitting Pull Requests

Ready to contribute code? Here's how:

1. **Find or create an issue** describing what you want to work on.
2. **Comment on the issue** to let others know you're working on it.
3. **Fork the repository** and create a feature branch.
4. **Make your changes** following our coding standards.
5. **Test your changes** thoroughly.
6. **Submit a pull request** referencing the related issue.

---

## Development Setup

### Prerequisites

- Rust (stable + nightly toolchain)
- Cargo

### Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-username>/Scilla.git
cd Scilla

# Add upstream remote
git remote add upstream https://github.com/blueshift-gg/Scilla.git

# Install dependencies and build
cargo build

# Run the application
cargo run
```

### Running Checks Locally

Before submitting a PR, ensure all checks pass:

```bash
# Run all checks at once
make all-checks

# Or run individually:
make format      # Check formatting
make clippy      # Run linter
make test        # Run tests
make check-features  # Check feature combinations
```

To auto-fix formatting and some clippy warnings:

```bash
make format-fix
make clippy-fix
```

---

## Pull Request Guidelines

### Before Submitting

- [ ] I've searched for duplicate issues/PRs
- [ ] I've discussed the change in an issue (for new features)
- [ ] My changes are based on the latest `master` branch
- [ ] I've run `make all-checks` and all checks pass
- [ ] I've added/updated tests if applicable
- [ ] I've updated documentation if needed

### PR Title and Description

- Use a clear, descriptive title (e.g., "feat: Add transfer command to Account module")
- Reference related issues using keywords (e.g., "Fixes #123", "Closes #456")
- Describe what changes you made and why
- Include any relevant context or screenshots

### PR Size

- **Keep PRs focused and small** — One feature or fix per PR
- Large PRs are harder to review and more likely to have conflicts
- If your change is large, consider breaking it into smaller PRs

### Responding to Reviews

- Be responsive to feedback
- Push fixes as new commits (don't force-push during review)
- Mark conversations as resolved when addressed

---

## Coding Standards

### Rust Style

- Follow standard Rust conventions and idioms
- Use `rustfmt` for consistent formatting (run `make format-fix`)
- Address all `clippy` warnings (run `make clippy`)
- Write descriptive variable and function names
- Add comments for complex logic

### Commit Messages

Write clear, meaningful commit messages:

```
<type>: <short summary>

[optional body with more details]

[optional footer with issue references]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**

```
feat: add balance command to Account module

fix: handle RPC timeout errors gracefully

docs: update README with new commands
```

### Testing

- Write tests for new functionality
- Ensure existing tests pass
- Test edge cases and error conditions

---

## License

By contributing to Scilla, you agree that your contributions will be licensed under the same dual license as the project: [Apache License 2.0](./LICENSE-APACHE) or [MIT License](./LICENSE-MIT), at the user's option.

---

## Questions?

If you have questions about contributing, feel free to join [Blueshift Discord server](https://discord.gg/blueshift) ask in the #scilla channel.

Thank you for helping make Scilla and Solana better!
