# Contributing to soft-canonicalize

Thanks for your interest in contributing! 🦀

## Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/soft-canonicalize-rs.git`
3. **Test** locally:
   - **Linux/macOS/WSL**: `bash ci-local.sh`
   - **Windows PowerShell**: `.\ci-local.ps1`
   - Both scripts run all CI checks including security audit
4. **Submit** a pull request

All PRs automatically run CI on Windows, Linux, and macOS with security auditing.

## How to Contribute

- **🐛 Bug reports**: [Open an issue](https://github.com/DK26/soft-canonicalize-rs/issues) with reproduction steps
- **💡 Features**: Discuss in an issue before implementing
- **📝 Docs**: Fix typos, add examples, improve clarity
- **🔧 Code**: Bug fixes and improvements welcome

## Development

**Project Philosophy:**

- **std compatibility** - Match `std::fs::canonicalize` behavior for existing paths
- **Zero dependencies** - Keep it lightweight
- **Cross-platform** - Windows, Linux, macOS
- **Security focused** - Proper symlink and `..` handling with automated security auditing
- **Pure algorithm** - No filesystem modification

## AI Prompt

Copy-paste this when working with AI on this project:

```text
Rules: Always run `bash ci-local.sh` or `.\ci-local.ps1` before committing. This project must maintain 100% behavioral compatibility with std::fs::canonicalize for existing paths while extending to non-existing paths. Never remove existing APIs, tests, or break std compatibility. All std library compatibility tests must continue to pass. Preserve security features like symlink cycle detection and security auditing. Avoid redundant explanations in documentation.
```

## What We Want ✅

- Bug fixes and performance improvements
- Better error handling and documentation
- Cross-platform compatibility fixes
- Additional security tests and examples
- std library compatibility improvements

## What We Don't Want ❌

- Breaking changes to std compatibility (discuss first)
- New dependencies (unless strongly justified)
- Behavior changes that break existing tests
- Features that compromise security

## Testing

**Simple**: Just run the CI script locally:

```bash
# Linux/macOS/WSL
bash ci-local.sh

# Windows PowerShell  
.\ci-local.ps1
```

This runs all checks (format, clippy, tests, docs, security audit, MSRV) and ensures std compatibility. If it passes, your code is ready.

**Test Coverage**: The project has 299 tests total:

- 78 unit tests (in `src/tests/`)
- 6 complex attack tests (blackbox security)  
- 9 security tests (comprehensive security coverage)
- 11 compatibility tests (std library compatibility)
- 164 integration tests (in `tests/` directory)
- 4 documentation tests
- 8 anchored canonicalization tests (with `--features anchored`)

The CI runs tests in both default and all-features configurations.

**Project Structure**: 
- `src/` - Main library code and unit tests
- `examples/` - User-facing examples (essential examples only)
- `examples/archive/` - Historical examples from optimization work
- `benches/` - Performance benchmarks vs Python baseline
- `benches/python/` - Historical Python investigation scripts
- `tests/` - Integration and blackbox security tests

**Benchmarks**: Performance benchmarks are in `benches/` and can be run with `cargo bench`. See `benches/README.md` for details (Linux/WSL prefers `python3.13` for baseline; use 5-run median protocol).

**Performance Testing**: See [`benches/README.md`](benches/README.md) for a step-by-step guide and the 5-run median protocol.

**Examples**: See `examples/` directory for usage examples and demonstrations.

## License

By contributing, you agree that your contributions will be licensed under **MIT OR Apache-2.0**.

You confirm that:

- You have the right to submit your contribution
- Your contribution is your original work or properly attributed

## Getting Help

- **Issues**: Bug reports and feature requests
- **Email**: <dikaveman@gmail.com>

---

Every contribution matters! 🚀
