/**
 * @file rules.h
 * @brief Vulnerability detection rules mapping CWE definitions to static analysis logic.
 * @project c-security-auditor
 */

#ifndef RULES_H
#define RULES_H

#include "scanner.h"

/**
 * @brief Metadata definition for dangerous C runtime function calls.
 */
typedef struct {
    const char *rule_id;
    const char *cwe_id;
    const char *cwe_name;
    Severity severity;
    const char *function_name;
    const char *message;
    const char *remediation;
} FunctionRule;

/**
 * @brief Initialize static analysis rules registry.
 */
void rules_init(void);

/**
 * @brief Execute all registered security rules against a loaded source file.
 *
 * @param file Pointer to loaded SourceFile.
 * @param findings Pointer to findings list where detected issues are collected.
 * @param stats Pointer to scan stats to update counters.
 */
void rules_analyze_file(const SourceFile *file, FindingList *findings, ScanStats *stats);

#endif /* RULES_H */
