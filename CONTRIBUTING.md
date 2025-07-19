# Contributing to soft-canonicalize

Thanks for your interest in contributing! 🦀

## Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/soft-canonicalize-rs.git`
3. **Test** locally: `bash ci-local.sh` (runs all CI checks)
4. **Submit** a pull request

All PRs automatically run CI on Windows, Linux, and macOS.

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
- **Security focused** - Proper symlink and `..` handling
- **Pure algorithm** - No filesystem modification

## AI Prompt

Copy-paste this when working with AI on this project:

```
Rules: Always run `bash ci-local.sh` before committing. This project must maintain 100% behavioral compatibility with std::fs::canonicalize for existing paths while extending to non-existing paths. Never remove existing APIs, tests, or break std compatibility. All std library compatibility tests must continue to pass. Preserve security features like symlink cycle detection. Avoid redundant explanations in documentation.
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
bash ci-local.sh
```

This runs all checks (format, clippy, tests, docs, MSRV) and ensures std compatibility. If it passes, your code is ready.

## License

By contributing, you agree that your contributions will be licensed under **MIT OR Apache-2.0**.

You confirm that:
- You have the right to submit your contribution
- Your contribution is your original work or properly attributed

## Getting Help

- **Issues**: Bug reports and feature requests
- **Email**: dikaveman@gmail.com

---

Every contribution matters! 🚀
