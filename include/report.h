/**
 * @file report.h
 * @brief Report formatting interfaces for Terminal (ANSI), Markdown, and JSON.
 * @project c-security-auditor
 */

#ifndef REPORT_H
#define REPORT_H

#include "scanner.h"

/**
 * @brief Output report format options.
 */
typedef enum {
    FORMAT_TERMINAL = 0,
    FORMAT_MARKDOWN,
    FORMAT_JSON
} ReportFormat;

/**
 * @brief Initialize terminal environment (enables ANSI Virtual Terminal on Windows).
 */
void terminal_init(void);

/**
 * @brief Convert a Severity enum to its human-readable uppercase string.
 */
const char *severity_to_string(Severity sev);

/**
 * @brief Get ANSI color escape sequence associated with a Severity level.
 */
const char *severity_color_ansi(Severity sev);

/**
 * @brief Print colored DevSecOps audit findings report directly to stdout.
 *
 * @param findings Pointer to collection of findings.
 * @param stats Scan statistics metrics.
 * @param show_suppressed Whether suppressed warnings should be displayed.
 */
void report_terminal(const FindingList *findings, const ScanStats *stats, bool show_suppressed);

/**
 * @brief Export audit findings to a GitHub-flavored Markdown file.
 *
 * @param output_file Destination file path.
 * @param findings Pointer to collection of findings.
 * @param stats Scan statistics metrics.
 * @param target_path Root scan target path for metadata.
 * @return 0 on success, non-zero on I/O error.
 */
int report_markdown(const char *output_file, const FindingList *findings, const ScanStats *stats, const char *target_path);

/**
 * @brief Export audit findings to a structured JSON file.
 *
 * @param output_file Destination file path.
 * @param findings Pointer to collection of findings.
 * @param stats Scan statistics metrics.
 * @param target_path Root scan target path for metadata.
 * @return 0 on success, non-zero on I/O error.
 */
int report_json(const char *output_file, const FindingList *findings, const ScanStats *stats, const char *target_path);

#endif /* REPORT_H */
