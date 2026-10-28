---
name: c-security-auditor-harness
description: Engineering specification, architecture documentation, and AI agent instructions for auditing, maintaining, and extending the c-security-auditor SAST engine.
version: 1.0.0
standard: ISO/IEC 9899:2011 (C11)
---

# 🤖 c-security-auditor :: AI Agent & Engineering Skill Harness

Welcome to the internal specification and rule authoring harness for **c-security-auditor**, an industrial-grade Static Application Security Testing (SAST) tool written in pure C11. This document defines the engine architecture, parsing methodologies, suppression mechanisms, and the formal protocol for extending the vulnerability rule catalog.

---

## 1. Engine Architectural Overview

```
+--------------------------------------------------------------------------+
|                          c-security-auditor CLI                          |
+--------------------------------------------------------------------------+
                                     |
                                     v
+------------------+     +--------------------+     +----------------------+
| Ingestion Engine | --> | Lexical Masking    | --> | Rule Registry        |
| (scanner.c)      |     | (rules.c)          |     | (rules.c)            |
| - Directory walk |     | - Strip block/line |     | - Dangerous funcs    |
| - Memory buffer  |     |   comments         |     | - Unbounded scanf    |
| - Line tracking  |     | - Mask str literals|     | - Unchecked allocs   |
+------------------+     +--------------------+     +----------------------+
                                                               |
                                                               v
+------------------+     +--------------------+     +----------------------+
| Terminal (ANSI)  | <-- | Policy Gate        | <-- | Finding List Engine  |
| Markdown Report  |     | (main.c)           |     | (scanner.c)          |
| JSON DevSecOps   |     | - Threshold check  |     | - Severity CVSS      |
| (report.c)       |     | - Exit code 0 / 1  |     | - Suppression check  |
+------------------+     +--------------------+     +----------------------+
```

### Core Design Principles:
1. **Zero-Dependency Portability:** Written in ISO C11 with zero external libraries. Compiles cleanly across Linux, macOS, and Windows (MinGW/MSYS2).
2. **Lexical Masking Before Analysis:** Comments (`//`, `/* ... */`) and string literals (`"..."`) are masked with whitespace *prior* to matching identifiers. This completely eliminates false positives caused by documentation comments or debug logging while preserving 1-to-1 column offsets.
3. **Multi-Line Lookahead Window:** State-aware verification (e.g., checking if `malloc()` return pointer is checked against `NULL`) examines a forward sliding window of statements until block termination (`}`).
4. **Non-Invasive Inline Suppression:** The `// sast-ignore` tag operates on the exact target line or the immediately preceding line, giving engineers full audit-trail control.

---

## 2. Currently Implemented Rules Matrix

| Rule ID | Target CWE | CVSS Severity | Description | Remediation |
| :--- | :--- | :---: | :--- | :--- |
| `RULE_CWE_242_GETS` | **CWE-242** | `CRITICAL` | Inherently dangerous unbounded input read | Replace with `fgets(buf, sizeof(buf), stdin)` |
| `RULE_CWE_120_STRCPY` | **CWE-120** | `HIGH` | Buffer copy without length checking | Replace with `strncpy()` or `snprintf()` |
| `RULE_CWE_120_STRCAT` | **CWE-120** | `HIGH` | Concatenation without destination bounds | Use bounded `strncat()` or `snprintf()` |
| `RULE_CWE_120_SPRINTF` | **CWE-120** | `HIGH` | Formatting output without buffer boundary | Replace with `snprintf(dest, sizeof(dest), ...)` |
| `RULE_CWE_78_SYSTEM` | **CWE-78** | `HIGH` | Arbitrary command injection via shell | Avoid shell; use parameterized exec APIs |
| `RULE_CWE_120_SCANF_UNBOUNDED` | **CWE-120** | `HIGH` | Unbounded `%s` or `%[` in scanf format | Specify maximum width, e.g. `"%63s"` |
| `RULE_CWE_252_UNCHECKED_ALLOC` | **CWE-252** / **CWE-401** | `HIGH` | `malloc`/`calloc`/`realloc` without NULL test | Test `if (!ptr)` immediately before use |

---

## 3. Protocol for Adding New Vulnerability Rules

When instructed to add a new security rule or CWE detection, follow this exact 5-step engineering protocol:

### Step 1: Declare Rule Definition in `src/rules.c`
If adding a function call rule, add an entry to the `DANGEROUS_FUNCS` table:
```c
{
    .rule_id = "RULE_CWE_134_PRINTF",
    .cwe_id = "CWE-134",
    .cwe_name = "Use of Externally-Controlled Format String",
    .severity = SEV_HIGH,
    .function_name = "printf",
    .message = "Direct passing of non-literal argument as format string risks format string exploitation.",
    .remediation = "Always provide a static format string literal: 'printf(\"%s\", user_str)'."
}
```

### Step 2: Implement Syntax Check / Token Verification
If the rule requires deeper structural analysis (e.g. checking whether the first argument of `printf` is a string literal), implement a dedicated verification helper:
```c
static bool is_uncontrolled_format_string(const char *raw_line, size_t col) {
    const char *p = raw_line + col - 1;
    const char *paren = strchr(p, '(');
    if (!paren) return false;
    paren++;
    while (*paren && isspace((unsigned char)*paren)) paren++;
    /* If first argument does not start with a double quote, flag CWE-134 */
    return (*paren != '"');
}
```

### Step 3: Register in `rules_analyze_file()`
Invoke your checker inside the per-line loop in `rules_analyze_file()`:
```c
if (is_uncontrolled_format_string(raw, col)) {
    Finding finding;
    memset(&finding, 0, sizeof(finding));
    safe_copy_str(finding.file_path, file->path, sizeof(finding.file_path));
    finding.line_number = src_line->number;
    finding.column_number = col;
    safe_copy_str(finding.rule_id, "RULE_CWE_134_PRINTF", sizeof(finding.rule_id));
    safe_copy_str(finding.cwe_id, "CWE-134", sizeof(finding.cwe_id));
    safe_copy_str(finding.cwe_name, "Use of Externally-Controlled Format String", sizeof(finding.cwe_name));
    finding.severity = SEV_HIGH;
    safe_copy_str(finding.message, "Non-literal format string passed to printf().", sizeof(finding.message));
    safe_copy_str(finding.snippet, raw, sizeof(finding.snippet));
    safe_copy_str(finding.remediation, "Use static literal: printf(\"%s\", var);", sizeof(finding.remediation));
    finding.suppressed = suppressed;

    finding_list_add(findings, &finding);
    if (suppressed) stats->suppressed_count++;
    else stats->high_count++;
}
```

### Step 4: Add Test Cases
1. In `tests/vulnerable_sample.c`: Add a function demonstrating the vulnerable construct.
2. In `tests/clean_sample.c`: Add the compliant/remediated pattern.

### Step 5: Verify Zero-Warning Build
Run `powershell .\build.ps1` on Windows or `make clean && make test` on Linux. Ensure zero warnings under `-Wall -Wextra -Werror -pedantic -std=c11`.

---

## 4. Agent Quality Checklist

Prior to submitting code modifications:
- [ ] Code compiles with `gcc -Wall -Wextra -Werror -pedantic -std=c11` with ZERO warnings.
- [ ] Line and column offsets in `Finding` match original source positions accurately.
- [ ] Comments containing rule names (e.g., `/* strcpy */`) do NOT trigger false positives.
- [ ] Inline suppression tag `// sast-ignore` correctly marks `finding.suppressed = true`.
- [ ] JSON report serializes valid RFC 8259 output without broken escape characters.
- [ ] Markdown report renders tables and badges correctly.
- [ ] Exit code 1 is returned when findings exceed `--fail-on` threshold; exit code 0 when clean.
