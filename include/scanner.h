/**
 * @file scanner.h
 * @brief Scanner core types, source representation, and directory traversal interfaces.
 * @project c-security-auditor
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_PATH_LEN 512
#define MAX_RULE_ID_LEN 64
#define MAX_CWE_LEN 32
#define MAX_NAME_LEN 128
#define MAX_MSG_LEN 256
#define MAX_SNIPPET_LEN 256
#define MAX_REMEDY_LEN 256
#define MAX_LINE_BUFFER 4096

/**
 * @brief Finding severity levels following CVSS-aligned classification.
 */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} Severity;

/**
 * @brief Representation of an individual security vulnerability detected.
 */
typedef struct {
    char file_path[MAX_PATH_LEN];
    size_t line_number;
    size_t column_number;
    char rule_id[MAX_RULE_ID_LEN];
    char cwe_id[MAX_CWE_LEN];
    char cwe_name[MAX_NAME_LEN];
    Severity severity;
    char message[MAX_MSG_LEN];
    char snippet[MAX_SNIPPET_LEN];
    char remediation[MAX_REMEDY_LEN];
    bool suppressed;
} Finding;

/**
 * @brief Dynamic array container for findings.
 */
typedef struct {
    Finding *items;
    size_t count;
    size_t capacity;
} FindingList;

/**
 * @brief Representation of a single source line with metadata.
 */
typedef struct {
    size_t number;
    char *content;
    bool has_suppression;
} SourceLine;

/**
 * @brief Representation of an entire loaded source file.
 */
typedef struct {
    char path[MAX_PATH_LEN];
    SourceLine *lines;
    size_t line_count;
    size_t capacity;
} SourceFile;

/**
 * @brief Aggregated scan metrics and performance statistics.
 */
typedef struct {
    size_t files_scanned;
    size_t lines_scanned;
    size_t critical_count;
    size_t high_count;
    size_t medium_count;
    size_t low_count;
    size_t info_count;
    size_t suppressed_count;
    double scan_duration_ms;
} ScanStats;

/* Source file management */
SourceFile *source_file_load(const char *path);
void source_file_free(SourceFile *sf);

/* Finding collection management */
FindingList *finding_list_create(void);
void finding_list_add(FindingList *list, const Finding *finding);
void finding_list_free(FindingList *list);

/* Suppression check */
bool is_line_suppressed(const char *line);

/* Scanning engine */
int scan_file(const char *file_path, FindingList *findings, ScanStats *stats);
int scan_directory(const char *dir_path, FindingList *findings, ScanStats *stats);
int scan_path(const char *target_path, FindingList *findings, ScanStats *stats);

#endif /* SCANNER_H */
