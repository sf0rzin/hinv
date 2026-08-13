# Security Policy

## Supported Versions

This is an experimental research project. Only the latest commit on `master` receives attention. There are no supported release branches.

## Reporting a Vulnerability

If you discover a security issue in `hinv`, please open a private GitHub issue or contact the maintainers directly. Do not disclose the vulnerability publicly until a fix is available.

## Scope

`hinv` is designed for **educational use in isolated virtual machines**. It manipulates kernel memory and loads vulnerable drivers. Do not run it on production systems, machines you do not own, or without explicit authorization.

## Safe Usage Guidelines

- Always use a disposable VM with snapshots.
- Never run `hinv` with elevated privileges on a host machine.
- Do not use `hinv` to target third-party systems.
- Assume that any kernel-mode operation may cause a bugcheck (BSOD).

## Known Risks

- **BSODs** are expected during development and testing.
- **Kernel memory corruption** may occur if offsets or signatures are incorrect for your Windows build.
- **Vulnerable driver compatibility** varies; `dbutil_2_3.sys` may be blocked by newer Windows versions.

## Disclaimer

The authors are not responsible for misuse, damage, or legal consequences resulting from the use of this software. Use at your own risk.
