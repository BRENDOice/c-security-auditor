/**
 * @file main.c
 * @brief Command-line interface and orchestrator for c-security-auditor.
 * @project c-security-auditor
 */

#include "scanner.h"
#include "rules.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VERSION "1.0.0"

static void print_banner(void) {
    printf("c-security-auditor v%s - C Static Application Security Testing (SAST)\n", VERSION);
    printf("DevSecOps memory safety & CWE auditing engine (C11)\n\n");
}

static void print_usage(const char *prog_name) {
    print_banner();
    printf("USAGE:\n");
    printf("  %s [options] <target-file-or-directory>\n\n", prog_name);
    printf("OPTIONS:\n");
    printf("  -o, --output <file>       Export report to specified file path\n");
    printf("  -f, --format <fmt>        Export format: 'markdown', 'json' (default: markdown if -o given)\n");
    printf("  -s, --show-suppressed     Display suppressed findings (marked with // sast-ignore)\n");
    printf("  --fail-on <severity>      Fail policy threshold: 'critical', 'high', 'medium', 'low', 'none'\n");
    printf("                            (default: 'high')\n");
    printf("  -v, --version             Display version information\n");
    printf("  -h, --help                Display this help documentation\n\n");
    printf("EXAMPLES:\n");
    printf("  %s src/\n", prog_name);
    printf("  %s tests/vulnerable_sample.c -o report.md -f markdown\n", prog_name);
    printf("  %s . -o audit.json -f json --fail-on critical\n\n", prog_name);
}

int main(int argc, char *argv[]) {
    terminal_init();
    rules_init();

    const char *target_path = NULL;
    const char *output_file = NULL;
    ReportFormat format = FORMAT_TERMINAL;
    bool show_suppressed = false;
    Severity fail_threshold = SEV_HIGH;
    bool fail_on_none = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("c-security-auditor version %s (C11 compliant)\n", VERSION);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--show-suppressed") == 0) {
            show_suppressed = true;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output_file = argv[++i];
                if (format == FORMAT_TERMINAL) {
                    format = FORMAT_MARKDOWN;
                }
            } else {
                fprintf(stderr, "Error: Flag '%s' requires a file path argument.\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
            if (i + 1 < argc) {
                i++;
                if (strcmp(argv[i], "markdown") == 0 || strcmp(argv[i], "md") == 0) {
                    format = FORMAT_MARKDOWN;
                } else if (strcmp(argv[i], "json") == 0) {
                    format = FORMAT_JSON;
                } else if (strcmp(argv[i], "terminal") == 0) {
                    format = FORMAT_TERMINAL;
                } else {
                    fprintf(stderr, "Error: Unsupported format '%s'. Choose 'markdown' or 'json'.\n", argv[i]);
                    return 2;
                }
            } else {
                fprintf(stderr, "Error: Flag '%s' requires a format argument ('markdown' or 'json').\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--fail-on") == 0) {
            if (i + 1 < argc) {
                i++;
                if (strcmp(argv[i], "critical") == 0) fail_threshold = SEV_CRITICAL;
                else if (strcmp(argv[i], "high") == 0) fail_threshold = SEV_HIGH;
                else if (strcmp(argv[i], "medium") == 0) fail_threshold = SEV_MEDIUM;
                else if (strcmp(argv[i], "low") == 0) fail_threshold = SEV_LOW;
                else if (strcmp(argv[i], "none") == 0) fail_on_none = true;
                else {
                    fprintf(stderr, "Error: Unknown severity threshold '%s'.\n", argv[i]);
                    return 2;
                }
            } else {
                fprintf(stderr, "Error: Flag '--fail-on' requires a severity level.\n");
                return 2;
            }
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unrecognized option '%s'. Run with --help for options.\n", argv[i]);
            return 2;
        } else {
            if (!target_path) {
                target_path = argv[i];
            } else {
                fprintf(stderr, "Error: Multiple target paths provided ('%s' and '%s').\n", target_path, argv[i]);
                return 2;
            }
        }
    }

    if (!target_path) {
        /* Default to scanning current directory if no path specified */
        target_path = ".";
    }

    FindingList *findings = finding_list_create();
    if (!findings) {
        fprintf(stderr, "Fatal: Out of memory allocating findings list.\n");
        return 2;
    }

    ScanStats stats;
    memset(&stats, 0, sizeof(stats));

    clock_t start_clock = clock();

    int scan_rc = scan_path(target_path, findings, &stats);
    if (scan_rc != 0) {
        fprintf(stderr, "Error: Failed to access target path '%s'. Check permissions or path existence.\n", target_path);
        finding_list_free(findings);
        return 2;
    }

    clock_t end_clock = clock();
    stats.scan_duration_ms = ((double)(end_clock - start_clock) / (double)CLOCKS_PER_SEC) * 1000.0;

    /* Always print terminal summary to stdout */
    report_terminal(findings, &stats, show_suppressed);

    /* Export report if requested */
    if (output_file) {
        int export_rc = 0;
        if (format == FORMAT_MARKDOWN) {
            export_rc = report_markdown(output_file, findings, &stats, target_path);
        } else if (format == FORMAT_JSON) {
            export_rc = report_json(output_file, findings, &stats, target_path);
        }

        if (export_rc == 0) {
            printf("[+] Successfully exported report to: %s\n\n", output_file);
        } else {
            fprintf(stderr, "[-] Warning: Failed to write report file '%s'.\n\n", output_file);
        }
    }

    /* Policy gate check */
    bool policy_failed = false;
    if (!fail_on_none) {
        if (fail_threshold <= SEV_CRITICAL && stats.critical_count > 0) policy_failed = true;
        if (fail_threshold <= SEV_HIGH && stats.high_count > 0) policy_failed = true;
        if (fail_threshold <= SEV_MEDIUM && stats.medium_count > 0) policy_failed = true;
        if (fail_threshold <= SEV_LOW && stats.low_count > 0) policy_failed = true;
    }

    finding_list_free(findings);

    return policy_failed ? 1 : 0;
}
