# 🛡️ c-security-auditor

[![Build & SAST](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=for-the-badge&logo=githubactions)](https://github.com/)
[![Standard](https://img.shields.io/badge/Standard-C11%20(ISO%2FIEC%209899%3A2011)-blue.svg?style=for-the-badge&logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Compiler Constraints](https://img.shields.io/badge/GCC-Wall%20Wextra%20Werror%20pedantic-success.svg?style=for-the-badge)](https://gcc.gnu.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg?style=for-the-badge)](LICENSE)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-orange.svg?style=for-the-badge)](https://owasp.org/)

An industrial-grade, zero-dependency **Static Application Security Testing (SAST)** engine written in strict standard C (C11). Engineered for high-throughput DevSecOps pipelines, automated quality gates, and systems-level vulnerability prevention in C and C++ codebases.

---

## 🏛️ System Architecture

```
                    c-security-auditor Architecture
                    ===============================

             [ Source Code Input: *.c / *.h / Directories ]
                                    |
                                    v
       +---------------------------------------------------------+
       |                  SCANNER ENGINE (scanner.c)             |
       |  - Recursive Directory Traversal (POSIX / MinGW)        |
       |  - Line-Buffered Stream Ingestion                       |
       |  - Comment & Directive Pre-Processor                    |
       |  - Inline Suppression Detection ("// sast-ignore")     |
       +---------------------------------------------------------+
                                    |
                                    v
       +---------------------------------------------------------+
       |                   RULES ENGINE (rules.c)                |
       |  - Lexical Token Masking (Strings & Block Comments)     |
       |  - Word-Boundary Identifier Matching                    |
       |  - Unbounded Format Specifier Parsing                   |
       |  - Multi-Line Lookahead Allocation NULL Validation      |
       +---------------------------------------------------------+
                                    |
                                    v
       +---------------------------------------------------------+
       |                  POLICY GATE (main.c)                   |
       |  - CVSS Severity Aggregator                             |
       |  - Policy Gate Thresholding (--fail-on critical/high)   |
       |  - Process Exit Code Dispatch (0 = Clean, 1 = Violation)|
       +---------------------------------------------------------+
                                    |
                     +--------------+--------------+
                     |                             |
                     v                             v
       +---------------------------+ +---------------------------+
       |   TERMINAL REPORTER       | |     EXPORTERS (report.c)  |
       |  - TrueColor ANSI Escape  | |  - GitHub Flavored MD     |
       |  - Source Line Indicator  | |  - RFC 8259 Compliant     |
       |  - Executive Metrics Box  | |    Structured JSON        |
       +---------------------------+ +---------------------------+
```

---

## 🎯 Vulnerability Detection Matrix

`c-security-auditor` scans source code against high-risk memory corruption, buffer overflow, and command execution CWE patterns:

| CWE ID | Common Vulnerability Enumeration | Severity | Defective Pattern | Secure Alternative |
| :---: | :--- | :---: | :--- | :--- |
| **CWE-242** | Use of Inherently Dangerous Function | `CRITICAL` | `gets(buf)` | `fgets(buf, sizeof(buf), stdin)` |
| **CWE-120** | Buffer Copy without Checking Size | `HIGH` | `strcpy(dest, src)` | `strncpy()` or `snprintf()` |
| **CWE-120** | Buffer Copy without Checking Size | `HIGH` | `strcat(dest, src)` | `strncat()` with remaining capacity |
| **CWE-120** | Buffer Copy without Checking Size | `HIGH` | `sprintf(dest, ...)` | `snprintf(dest, sizeof(dest), ...)` |
| **CWE-78** | OS Command Injection | `HIGH` | `system(cmd)` | Parameterized execution (`execve`) |
| **CWE-120** | Unbounded Input Capture | `HIGH` | `scanf("%s", ...)` | Width-bounded format: `scanf("%63s", ...)` |
| **CWE-252**<br>**CWE-401** | Unchecked Allocation / Leak Risk | `HIGH` | `malloc(...)` without `if (!ptr)` check | Immediate validation: `if (!ptr) { ... }` |

---

## 🚀 Quickstart Guide

### 🪟 Windows (PowerShell)

The included `build.ps1` script automates compilation with GCC and immediately runs verification:

```powershell
# 1. Build and run automated test suite
cd c-security-auditor
.\build.ps1

# 2. Audit a specific file or directory
.\build\c-security-auditor.exe tests\vulnerable_sample.c

# 3. Export a Markdown audit report
.\build\c-security-auditor.exe src\ -o report.md -f markdown

# 4. Export a JSON report for CI/CD ingestion
.\build\c-security-auditor.exe src\ -o audit.json -f json
```

### 🐧 Linux / macOS (Makefile)

A cross-platform Makefile compiles cleanly with zero warnings under `-Wall -Wextra -Werror -pedantic -std=c11`:

```bash
# 1. Build the auditor binary
cd c-security-auditor
make

# 2. Run automated test suite
make test

# 3. Scan codebase and export Markdown report
./build/c-security-auditor src/ -o security_report.md -f markdown

# 4. Optional: Install system-wide to /usr/local/bin
sudo make install
```

---

## ⚙️ Command-Line Interface (CLI)

```
USAGE:
  c-security-auditor [options] <target-file-or-directory>

OPTIONS:
  -o, --output <file>       Export report to specified file path
  -f, --format <fmt>        Export format: 'markdown', 'json' (default: markdown if -o given)
  -s, --show-suppressed     Display suppressed findings (marked with // sast-ignore)
  --fail-on <severity>      Policy failure threshold: 'critical', 'high', 'medium', 'low', 'none'
                            (default: 'high')
  -v, --version             Display version information
  -h, --help                Display help documentation
```

### Exit Codes for CI/CD Gates
- **`0`**: Scan succeeded and no findings exceed the `--fail-on` threshold.
- **`1`**: Security violations found that violate policy gate rules.
- **`2`**: Invalid CLI syntax, inaccessible target path, or memory failure.

---

## 🛡️ False-Positive Management: `// sast-ignore`

To suppress an intentional legacy construct or an accepted security exception, append `// sast-ignore` to the affected line or place it on the line immediately preceding the statement:

```c
/* Example 1: Same-line suppression */
strcpy(legacy_buffer, "known_static_literal"); // sast-ignore

/* Example 2: Preceding-line suppression */
// sast-ignore
system("echo Audit checkpoint reached");
```

Suppressed findings are excluded from terminal failure checks and documented separately under the `SUPPRESSED` metric. To audit suppressed exceptions, pass the `--show-suppressed` flag.

---

## 🔄 CI/CD DevSecOps Pipeline

Integrate `c-security-auditor` into your GitHub Actions workflow (`.github/workflows/sast.yml`):

```yaml
name: SAST Quality Gate

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Auditor
        run: |
          make -C c-security-auditor
      - name: Security Audit Gate
        run: |
          ./c-security-auditor/build/c-security-auditor src/ \
            -o sast_report.md -f markdown --fail-on high
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sast-audit-report
          path: sast_report.md
```

---

## 📄 License

Distributed under the **MIT License**. Free for commercial and open-source DevSecOps adoption.
