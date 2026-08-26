# Security Policy & Defensive Engineering Declaration

## 🛡️ Defensive Purpose & Academic Scope

This project is strictly an **educational, research, and defensive endpoint detection prototype**. 

### Important Safety Constraints:
- **No Real Ransomware**: This project does **NOT** contain real ransomware, ransomware payloads, malicious encryption ciphers, credential theft mechanisms, data exfiltration logic, or network propagation worms.
- **Sandbox Boundary Enforcement**: All simulation scripts (`SafeRansomwareSimulator`) are hardcoded with path boundary validation (`_enforce_safe_path`). If an operation attempts to touch any path outside `test_environment/`, execution immediately terminates with a `SafetyViolationError`.
- **System Service Protection**: The `ProcessTerminator` engine maintains an immutable system process whitelist preventing accidental termination of critical OS services (e.g. `launchd`, `kernel_task`, `Finder`, `explorer.exe`, or PID 0/1).

---

## 🔒 Responsible Disclosure & Vulnerability Reporting

If you discover any security issues, vulnerabilities, or safety oversights within this codebase:

1. **Do NOT open a public GitHub issue.**
2. Please email the maintainer privately or open a private GitHub Security Advisory.
3. Provide a clear reproduction script and threat impact assessment.

We take defensive security integrity seriously and will respond to reported vulnerabilities promptly.
