/**
 * @file report.c
 * @brief Output report generator supporting ANSI terminal, GitHub-flavored Markdown,
 *        and structured JSON formats for DevSecOps pipelines.
 * @project c-security-auditor
 */

#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

/* ANSI Escape Codes */
#define COLOR_RESET       "\033[0m"
#define COLOR_BOLD        "\033[1m"
#define COLOR_DIM         "\033[2m"
#define COLOR_RED         "\033[31m"
#define COLOR_GREEN       "\033[32m"
#define COLOR_YELLOW      "\033[33m"
#define COLOR_BLUE        "\033[34m"
#define COLOR_MAGENTA     "\033[35m"
#define COLOR_CYAN        "\033[36m"
#define COLOR_WHITE       "\033[37m"
#define COLOR_BOLD_RED    "\033[1;31m"
#define COLOR_BOLD_GREEN  "\033[1;32m"
#define COLOR_BOLD_YELLOW "\033[1;33m"
#define COLOR_BOLD_CYAN   "\033[1;36m"
#define COLOR_BG_RED      "\033[41;37m"

void terminal_init(void) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
}

const char *severity_to_string(Severity sev) {
    switch (sev) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        case SEV_INFO:
        default:           return "INFO";
    }
}

const char *severity_color_ansi(Severity sev) {
    switch (sev) {
        case SEV_CRITICAL: return COLOR_BOLD_RED;
        case SEV_HIGH:     return COLOR_RED;
        case SEV_MEDIUM:   return COLOR_YELLOW;
        case SEV_LOW:      return COLOR_CYAN;
        case SEV_INFO:
        default:           return COLOR_BLUE;
    }
}

/**
 * @brief Helper to trim leading/trailing whitespace from code snippets.
 */
static const char *trim_snippet(const char *str) {
    if (!str) return "";
    while (*str && (*str == ' ' || *str == '\t')) {
        str++;
    }
    return str;
}

/**
 * @brief Escapes string characters for safe JSON serialization.
 */
static void json_write_escaped_string(FILE *fp, const char *str) {
    if (!str) {
        fputs("\"\"", fp);
        return;
    }
    fputc('"', fp);
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b", fp); break;
            case '\f': fputs("\\f", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    fprintf(fp, "\\u%04x", (unsigned char)*p);
                } else {
                    fputc(*p, fp);
                }
                break;
        }
    }
    fputc('"', fp);
}

void report_terminal(const FindingList *findings, const ScanStats *stats, bool show_suppressed) {
    printf("\n%s%s================================================================================%s\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%s       C-SECURITY-AUDITOR :: STATIC APPLICATION SECURITY TESTING (SAST)         %s\n",
           COLOR_BOLD, COLOR_WHITE, COLOR_RESET);
    printf("%s%s================================================================================%s\n\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);

    size_t active_count = 0;
    for (size_t i = 0; i < findings->count; i++) {
        if (!findings->items[i].suppressed) {
            active_count++;
        }
    }

    if (findings->count == 0 || (active_count == 0 && !show_suppressed)) {
        printf("%s%s[+] SCAN RESULT: CLEAN - No active vulnerabilities detected.%s\n\n",
               COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    } else {
        printf("%s%s[!] AUDIT FINDINGS DETAILS:%s\n\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET);

        for (size_t i = 0; i < findings->count; i++) {
            const Finding *f = &findings->items[i];

            if (f->suppressed && !show_suppressed) {
                continue;
            }

            const char *sev_color = severity_color_ansi(f->severity);
            const char *sev_str = severity_to_string(f->severity);

            if (f->suppressed) {
                printf("%s[%s - SUPPRESSED]%s %s%s:%zu:%zu%s\n",
                       COLOR_DIM, sev_str, COLOR_RESET,
                       COLOR_WHITE, f->file_path, f->line_number, f->column_number, COLOR_RESET);
            } else {
                printf("%s[%-8s]%s %s%s:%zu:%zu%s  %s(%s: %s)%s\n",
                       sev_color, sev_str, COLOR_RESET,
                       COLOR_WHITE, f->file_path, f->line_number, f->column_number, COLOR_RESET,
                       COLOR_CYAN, f->cwe_id, f->cwe_name, COLOR_RESET);
            }

            printf("    %sRule:%s         %s\n", COLOR_DIM, COLOR_RESET, f->rule_id);
            printf("    %sMessage:%s      %s\n", COLOR_DIM, COLOR_RESET, f->message);
            printf("    %sLine %zu:%s      %s%s%s\n",
                   COLOR_DIM, f->line_number, COLOR_RESET,
                   COLOR_BOLD, trim_snippet(f->snippet), COLOR_RESET);
            printf("    %sRemediation:%s  %s%s%s\n\n",
                   COLOR_DIM, COLOR_RESET,
                   COLOR_GREEN, f->remediation, COLOR_RESET);
        }
    }

    /* Print Summary Metrics */
    printf("%s%s--------------------------------------------------------------------------------%s\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
    printf("%s%sAUDIT SUMMARY & METRICS%s\n", COLOR_BOLD, COLOR_WHITE, COLOR_RESET);
    printf("%s%s--------------------------------------------------------------------------------%s\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);

    printf("  Files Scanned:        %zu\n", stats->files_scanned);
    printf("  Lines Scanned:        %zu\n", stats->lines_scanned);
    printf("  Execution Time:       %.2f ms\n", stats->scan_duration_ms);
    printf("  Total Findings:       %zu\n", findings->count);
    printf("    - %sCritical:%s         %zu\n", COLOR_BOLD_RED, COLOR_RESET, stats->critical_count);
    printf("    - %sHigh:%s             %zu\n", COLOR_RED, COLOR_RESET, stats->high_count);
    printf("    - %sMedium:%s           %zu\n", COLOR_YELLOW, COLOR_RESET, stats->medium_count);
    printf("    - %sLow:%s              %zu\n", COLOR_CYAN, COLOR_RESET, stats->low_count);
    printf("    - %sSuppressed:%s       %zu\n", COLOR_DIM, COLOR_RESET, stats->suppressed_count);

    bool failed = (stats->critical_count > 0 || stats->high_count > 0);
    printf("\n  Policy Gate Status:   %s%s%s\n",
           failed ? COLOR_BOLD_RED : COLOR_BOLD_GREEN,
           failed ? "FAILED (Vulnerabilities exceed security threshold)" : "PASSED (Security gate approved)",
           COLOR_RESET);
    printf("%s%s================================================================================%s\n\n",
           COLOR_BOLD, COLOR_CYAN, COLOR_RESET);
}

int report_markdown(const char *output_file, const FindingList *findings, const ScanStats *stats, const char *target_path) {
    if (!output_file || !findings || !stats) return -1;

    FILE *fp = fopen(output_file, "w");
    if (!fp) return -1;

    time_t now = time(NULL);
    char time_str[64];
    struct tm *tm_info = gmtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    bool failed = (stats->critical_count > 0 || stats->high_count > 0);

    fprintf(fp, "# 🛡️ SAST Security Audit Report\n\n");
    fprintf(fp, "> Static Application Security Testing generated by **c-security-auditor**\n\n");

    /* Status Banner */
    if (failed) {
        fprintf(fp, "![Status: FAILED](https://img.shields.io/badge/Security_Gate-FAILED-red.svg?style=for-the-badge) ");
    } else {
        fprintf(fp, "![Status: PASSED](https://img.shields.io/badge/Security_Gate-PASSED-green.svg?style=for-the-badge) ");
    }
    fprintf(fp, "![C Standards: C11](https://img.shields.io/badge/Standard-C11-blue.svg?style=for-the-badge) ");
    fprintf(fp, "![Type: SAST](https://img.shields.io/badge/Audit-SAST_DevSecOps-purple.svg?style=for-the-badge)\n\n");

    /* Metadata */
    fprintf(fp, "### 📋 Scan Metadata\n\n");
    fprintf(fp, "| Property | Value |\n");
    fprintf(fp, "| :--- | :--- |\n");
    fprintf(fp, "| **Target Path** | `%s` |\n", target_path ? target_path : ".");
    fprintf(fp, "| **Timestamp** | %s |\n", time_str);
    fprintf(fp, "| **Engine Version** | `c-security-auditor v1.0.0 (C11)` |\n");
    fprintf(fp, "| **Execution Duration** | `%.2f ms` |\n", stats->scan_duration_ms);
    fprintf(fp, "| **Policy Status** | **%s** |\n\n", failed ? "❌ FAILED" : "✅ PASSED");

    /* Executive Metrics Table */
    fprintf(fp, "### 📊 Metrics Summary\n\n");
    fprintf(fp, "| Severity | Active Findings | Suppressed | Threshold Limit |\n");
    fprintf(fp, "| :--- | :---: | :---: | :---: |\n");
    fprintf(fp, "| 🔴 **CRITICAL** | %zu | - | 0 allowed |\n", stats->critical_count);
    fprintf(fp, "| 🟠 **HIGH** | %zu | - | 0 allowed |\n", stats->high_count);
    fprintf(fp, "| 🟡 **MEDIUM** | %zu | - | Advisory |\n", stats->medium_count);
    fprintf(fp, "| 🔵 **LOW** | %zu | - | Advisory |\n", stats->low_count);
    fprintf(fp, "| ⚪ **SUPPRESSED** | - | %zu | Explicit via `// sast-ignore` |\n", stats->suppressed_count);
    fprintf(fp, "| 📁 **Files Scanned** | %zu | - | - |\n", stats->files_scanned);
    fprintf(fp, "| 📝 **Lines Scanned** | %zu | - | - |\n\n", stats->lines_scanned);

    /* Detailed Findings */
    fprintf(fp, "### 🔍 Vulnerability Findings Details\n\n");

    if (findings->count == 0) {
        fprintf(fp, "✅ **No security vulnerabilities were identified during this scan.**\n\n");
    } else {
        for (size_t i = 0; i < findings->count; i++) {
            const Finding *f = &findings->items[i];

            fprintf(fp, "#### Finding %zu: [%s] %s\n\n",
                    i + 1, severity_to_string(f->severity), f->cwe_name);

            if (f->suppressed) {
                fprintf(fp, "> ⚠️ **SUPPRESSED**: This alert has been ignored via inline comment `// sast-ignore`.\n\n");
            }

            fprintf(fp, "- **File:** `%s` (Line %zu, Col %zu)\n", f->file_path, f->line_number, f->column_number);
            fprintf(fp, "- **Rule:** `%s`\n", f->rule_id);
            fprintf(fp, "- **CWE Reference:** [%s: %s](https://cwe.mitre.org/data/definitions/%s.html)\n",
                    f->cwe_id, f->cwe_name, f->cwe_id + 4);
            fprintf(fp, "- **Vulnerability Description:** %s\n\n", f->message);

            fprintf(fp, "```c\n// Code snippet at line %zu\n%s\n```\n\n",
                    f->line_number, trim_snippet(f->snippet));

            fprintf(fp, "**Remediation Guidance:**\n> %s\n\n", f->remediation);
            fprintf(fp, "---\n\n");
        }
    }

    fprintf(fp, "### 📘 About c-security-auditor\n\n");
    fprintf(fp, "This report was autonomously produced by the Static Application Security Testing (SAST) tool for C codebases. "
                "Integrate this binary into your CI/CD quality gate to block memory safety vulnerabilities before deployment.\n");

    fclose(fp);
    return 0;
}

int report_json(const char *output_file, const FindingList *findings, const ScanStats *stats, const char *target_path) {
    if (!output_file || !findings || !stats) return -1;

    FILE *fp = fopen(output_file, "w");
    if (!fp) return -1;

    time_t now = time(NULL);
    char time_str[64];
    struct tm *tm_info = gmtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    bool failed = (stats->critical_count > 0 || stats->high_count > 0);

    fprintf(fp, "{\n");
    fprintf(fp, "  \"tool\": {\n");
    fprintf(fp, "    \"name\": \"c-security-auditor\",\n");
    fprintf(fp, "    \"version\": \"1.0.0\",\n");
    fprintf(fp, "    \"standard\": \"ISO/IEC 9899:2011 (C11)\",\n");
    fprintf(fp, "    \"category\": \"Static Application Security Testing (SAST)\"\n");
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"scan\": {\n");
    fprintf(fp, "    \"target\": ");
    json_write_escaped_string(fp, target_path ? target_path : ".");
    fprintf(fp, ",\n");
    fprintf(fp, "    \"timestamp\": \"%s\",\n", time_str);
    fprintf(fp, "    \"duration_ms\": %.2f,\n", stats->scan_duration_ms);
    fprintf(fp, "    \"files_scanned\": %zu,\n", stats->files_scanned);
    fprintf(fp, "    \"lines_scanned\": %zu\n", stats->lines_scanned);
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_findings\": %zu,\n", findings->count);
    fprintf(fp, "    \"critical\": %zu,\n", stats->critical_count);
    fprintf(fp, "    \"high\": %zu,\n", stats->high_count);
    fprintf(fp, "    \"medium\": %zu,\n", stats->medium_count);
    fprintf(fp, "    \"low\": %zu,\n", stats->low_count);
    fprintf(fp, "    \"info\": %zu,\n", stats->info_count);
    fprintf(fp, "    \"suppressed\": %zu,\n", stats->suppressed_count);
    fprintf(fp, "    \"policy_status\": \"%s\"\n", failed ? "FAILED" : "PASSED");
    fprintf(fp, "  },\n");

    fprintf(fp, "  \"findings\": [\n");
    for (size_t i = 0; i < findings->count; i++) {
        const Finding *f = &findings->items[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"id\": %zu,\n", i + 1);
        fprintf(fp, "      \"rule_id\": ");
        json_write_escaped_string(fp, f->rule_id);
        fprintf(fp, ",\n      \"cwe_id\": ");
        json_write_escaped_string(fp, f->cwe_id);
        fprintf(fp, ",\n      \"cwe_name\": ");
        json_write_escaped_string(fp, f->cwe_name);
        fprintf(fp, ",\n      \"severity\": \"%s\",\n", severity_to_string(f->severity));
        fprintf(fp, "      \"file\": ");
        json_write_escaped_string(fp, f->file_path);
        fprintf(fp, ",\n      \"line\": %zu,\n", f->line_number);
        fprintf(fp, "      \"column\": %zu,\n", f->column_number);
        fprintf(fp, "      \"snippet\": ");
        json_write_escaped_string(fp, trim_snippet(f->snippet));
        fprintf(fp, ",\n      \"message\": ");
        json_write_escaped_string(fp, f->message);
        fprintf(fp, ",\n      \"remediation\": ");
        json_write_escaped_string(fp, f->remediation);
        fprintf(fp, ",\n      \"suppressed\": %s\n", f->suppressed ? "true" : "false");
        fprintf(fp, "    }%s\n", (i + 1 < findings->count) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}
