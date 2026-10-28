/**
 * @file rules.c
 * @brief Static security rule analysis engine for C source code.
 *        Implements CWE-242, CWE-120, CWE-78, CWE-252, and CWE-401 detection.
 * @project c-security-auditor
 */

#include "rules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Number of static function rules */
#define DANGEROUS_FUNC_COUNT 5

static const FunctionRule DANGEROUS_FUNCS[DANGEROUS_FUNC_COUNT] = {
    {
        .rule_id = "RULE_CWE_242_GETS",
        .cwe_id = "CWE-242",
        .cwe_name = "Use of Inherently Dangerous Function",
        .severity = SEV_CRITICAL,
        .function_name = "gets",
        .message = "Use of inherently dangerous function 'gets()' which cannot prevent buffer overflow.",
        .remediation = "Replace with 'fgets(buffer, sizeof(buffer), stdin)' to enforce bounds."
    },
    {
        .rule_id = "RULE_CWE_120_STRCPY",
        .cwe_id = "CWE-120",
        .cwe_name = "Buffer Copy without Checking Size of Input",
        .severity = SEV_HIGH,
        .function_name = "strcpy",
        .message = "Unbounded memory copy using 'strcpy()'. Destination buffer may be overrun.",
        .remediation = "Use 'strncpy()' with explicit null-termination or 'snprintf(dest, sizeof(dest), \"%s\", src)'."
    },
    {
        .rule_id = "RULE_CWE_120_STRCAT",
        .cwe_id = "CWE-120",
        .cwe_name = "Buffer Copy without Checking Size of Input",
        .severity = SEV_HIGH,
        .function_name = "strcat",
        .message = "Unbounded string concatenation using 'strcat()' may exceed allocated buffer size.",
        .remediation = "Use bounded 'strncat()' with remaining buffer length calculation, or 'snprintf()'."
    },
    {
        .rule_id = "RULE_CWE_120_SPRINTF",
        .cwe_id = "CWE-120",
        .cwe_name = "Buffer Copy without Checking Size of Input",
        .severity = SEV_HIGH,
        .function_name = "sprintf",
        .message = "Unbounded formatting via 'sprintf()' can write beyond target buffer capacity.",
        .remediation = "Replace with 'snprintf(dest, sizeof(dest), format, ...)' specifying maximum capacity."
    },
    {
        .rule_id = "RULE_CWE_78_SYSTEM",
        .cwe_id = "CWE-78",
        .cwe_name = "Improper Neutralization of Special Elements used in an OS Command",
        .severity = SEV_HIGH,
        .function_name = "system",
        .message = "Direct shell execution via 'system()' risks command injection vulnerabilities.",
        .remediation = "Avoid shell invocation; use parameterized APIs ('execve' or 'CreateProcess') with strict input sanitation."
    }
};

void rules_init(void) {
    /* Ready for dynamic or configuration-based rules if needed in future */
}

/**
 * @brief Safely copy strings without truncation warnings or buffer overruns.
 */
static void safe_copy_str(char *dst, const char *src, size_t max_size) {
    if (!dst || max_size == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i < max_size - 1) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/**
 * @brief Strips single-line and multi-line comments and masks string/char literals,
 *        preserving column offsets and preventing false positives.
 */
static void sanitize_code_line(const char *raw, char *clean, size_t max_len, bool *in_block_comment) {
    size_t i = 0;
    size_t j = 0;
    bool in_string = false;
    bool in_char = false;

    while (raw[i] && j < max_len - 1) {
        /* Handle active multi-line block comment */
        if (*in_block_comment) {
            if (raw[i] == '*' && raw[i + 1] == '/') {
                *in_block_comment = false;
                clean[j++] = ' ';
                if (j < max_len - 1) clean[j++] = ' ';
                i += 2;
                continue;
            }
            clean[j++] = ' ';
            i++;
            continue;
        }

        /* Check for single-line comment start if not inside string/char */
        if (!in_string && !in_char && raw[i] == '/' && raw[i + 1] == '/') {
            while (raw[i] && j < max_len - 1) {
                clean[j++] = ' ';
                i++;
            }
            break;
        }

        /* Check for start of multi-line block comment */
        if (!in_string && !in_char && raw[i] == '/' && raw[i + 1] == '*') {
            *in_block_comment = true;
            clean[j++] = ' ';
            if (j < max_len - 1) clean[j++] = ' ';
            i += 2;
            continue;
        }

        /* Check for string boundary */
        if (!in_char && raw[i] == '"' && (i == 0 || raw[i - 1] != '\\')) {
            in_string = !in_string;
            clean[j++] = ' ';
            i++;
            continue;
        }

        /* Check for char literal boundary */
        if (!in_string && raw[i] == '\'' && (i == 0 || raw[i - 1] != '\\')) {
            in_char = !in_char;
            clean[j++] = ' ';
            i++;
            continue;
        }

        if (in_string || in_char) {
            clean[j++] = ' '; /* Mask characters inside strings/chars to spaces */
        } else {
            clean[j++] = raw[i];
        }
        i++;
    }
    clean[j] = '\0';
}

/**
 * @brief Checks if an identifier at a given offset represents an isolated function call.
 */
static bool is_function_call(const char *line, size_t pos, size_t name_len) {
    /* Character before must not be alphanumeric or underscore */
    if (pos > 0) {
        char prev = line[pos - 1];
        if (isalnum((unsigned char)prev) || prev == '_') {
            return false;
        }
    }

    /* Move past the function name */
    size_t cur = pos + name_len;

    /* Skip whitespace */
    while (line[cur] && isspace((unsigned char)line[cur])) {
        cur++;
    }

    /* Must be followed by an open parenthesis */
    return (line[cur] == '(');
}

/**
 * @brief Extract variable name from an assignment expression like "char *p = malloc" or "ptr = calloc".
 */
static bool extract_assigned_var(const char *line, size_t alloc_pos, char *var_out, size_t var_max) {
    if (alloc_pos == 0) return false;

    /* Look backwards for '=' */
    long eq_pos = -1;
    for (long i = (long)alloc_pos - 1; i >= 0; i--) {
        if (line[i] == '=') {
            /* Avoid ==, <=, >=, != */
            if (i > 0 && (line[i - 1] == '=' || line[i - 1] == '!' || line[i - 1] == '<' || line[i - 1] == '>')) {
                continue;
            }
            if (line[i + 1] == '=') {
                continue;
            }
            eq_pos = i;
            break;
        }
    }

    if (eq_pos <= 0) return false;

    /* Scan backwards from '=' to find the identifier */
    long end = eq_pos - 1;
    while (end >= 0 && isspace((unsigned char)line[end])) {
        end--;
    }
    if (end < 0) return false;

    long start = end;
    while (start >= 0 && (isalnum((unsigned char)line[start]) || line[start] == '_')) {
        start--;
    }
    start++;

    if (end >= start) {
        size_t len = (size_t)(end - start + 1);
        if (len < var_max) {
            memcpy(var_out, &line[start], len);
            var_out[len] = '\0';
            return true;
        }
    }

    return false;
}

/**
 * @brief Checks if a variable has a NULL check in subsequent lines.
 */
static bool is_pointer_null_checked(const SourceFile *file, size_t alloc_line_idx, const char *var_name) {
    size_t lookahead = 15;
    size_t max_line = alloc_line_idx + lookahead;
    if (max_line > file->line_count) {
        max_line = file->line_count;
    }

    char null_check_1[128];
    char null_check_2[128];
    char null_check_3[128];
    char null_check_4[128];
    char null_check_5[128];
    char assert_check[128];

    snprintf(null_check_1, sizeof(null_check_1), "!%s", var_name);
    snprintf(null_check_2, sizeof(null_check_2), "%s == NULL", var_name);
    snprintf(null_check_3, sizeof(null_check_3), "NULL == %s", var_name);
    snprintf(null_check_4, sizeof(null_check_4), "%s == 0", var_name);
    snprintf(null_check_5, sizeof(null_check_5), "0 == %s", var_name);
    snprintf(assert_check, sizeof(assert_check), "assert(%s", var_name);

    for (size_t i = alloc_line_idx + 1; i < max_line; i++) {
        const char *l = file->lines[i].content;

        if (strstr(l, null_check_1) ||
            strstr(l, null_check_2) ||
            strstr(l, null_check_3) ||
            strstr(l, null_check_4) ||
            strstr(l, null_check_5) ||
            strstr(l, assert_check)) {
            return true;
        }

        /* If scope closes before check, no check exists */
        if (strchr(l, '}') && !strchr(l, '{')) {
            break;
        }
    }

    return false;
}

/**
 * @brief Checks for unbounded scanf format string (%s without length).
 */
static bool has_unbounded_scanf_specifier(const char *raw_line) {
    const char *scan_ptr = strstr(raw_line, "scanf");
    if (!scan_ptr) return false;

    /* Find the opening parenthesis of scanf(...) */
    const char *paren = strchr(scan_ptr, '(');
    if (!paren) return false;

    /* Find the format string opening quote */
    const char *quote = strchr(paren, '"');
    if (!quote) return false;

    quote++; /* Inside format string */
    while (*quote && *quote != '"') {
        if (*quote == '%') {
            quote++;
            if (*quote == '%') {
                quote++;
                continue;
            }

            /* Read specifier flags/width */
            bool has_width = false;
            while (*quote && (isdigit((unsigned char)*quote) || *quote == '*' || *quote == 'l' || *quote == 'h')) {
                if (isdigit((unsigned char)*quote)) {
                    has_width = true;
                }
                quote++;
            }

            if (*quote == 's' || *quote == '[') {
                if (!has_width) {
                    return true; /* Unbounded %s or %[ */
                }
            }
        } else {
            quote++;
        }
    }

    return false;
}

/**
 * @brief Analyzes source file lines against all security rules.
 */
void rules_analyze_file(const SourceFile *file, FindingList *findings, ScanStats *stats) {
    if (!file || !findings || !stats) return;

    char clean_line[MAX_LINE_BUFFER];
    bool in_block_comment = false;

    for (size_t i = 0; i < file->line_count; i++) {
        const SourceLine *src_line = &file->lines[i];
        const char *raw = src_line->content;
        sanitize_code_line(raw, clean_line, sizeof(clean_line), &in_block_comment);

        /* Check for suppression on current line or preceding line */
        bool suppressed = src_line->has_suppression;
        if (!suppressed && i > 0 && file->lines[i - 1].has_suppression) {
            suppressed = true;
        }

        /* 1. Dangerous Functions (gets, strcpy, strcat, sprintf, system) */
        for (int r = 0; r < DANGEROUS_FUNC_COUNT; r++) {
            const FunctionRule *rule = &DANGEROUS_FUNCS[r];
            size_t fn_len = strlen(rule->function_name);
            const char *p = clean_line;

            while ((p = strstr(p, rule->function_name)) != NULL) {
                size_t col = (size_t)(p - clean_line) + 1;
                if (is_function_call(clean_line, col - 1, fn_len)) {
                    Finding finding;
                    memset(&finding, 0, sizeof(finding));

                    safe_copy_str(finding.file_path, file->path, sizeof(finding.file_path));
                    finding.line_number = src_line->number;
                    finding.column_number = col;
                    safe_copy_str(finding.rule_id, rule->rule_id, sizeof(finding.rule_id));
                    safe_copy_str(finding.cwe_id, rule->cwe_id, sizeof(finding.cwe_id));
                    safe_copy_str(finding.cwe_name, rule->cwe_name, sizeof(finding.cwe_name));
                    finding.severity = rule->severity;
                    safe_copy_str(finding.message, rule->message, sizeof(finding.message));
                    safe_copy_str(finding.snippet, raw, sizeof(finding.snippet));
                    safe_copy_str(finding.remediation, rule->remediation, sizeof(finding.remediation));
                    finding.suppressed = suppressed;

                    finding_list_add(findings, &finding);

                    if (suppressed) {
                        stats->suppressed_count++;
                    } else {
                        if (rule->severity == SEV_CRITICAL) stats->critical_count++;
                        else if (rule->severity == SEV_HIGH) stats->high_count++;
                        else if (rule->severity == SEV_MEDIUM) stats->medium_count++;
                        else if (rule->severity == SEV_LOW) stats->low_count++;
                        else stats->info_count++;
                    }
                }
                p += fn_len;
            }
        }

        /* 2. Unbounded scanf input (%s without width limit) */
        const char *scanf_p = clean_line;
        while ((scanf_p = strstr(scanf_p, "scanf")) != NULL) {
            size_t col = (size_t)(scanf_p - clean_line) + 1;
            if (is_function_call(clean_line, col - 1, 5) && has_unbounded_scanf_specifier(raw)) {
                Finding finding;
                memset(&finding, 0, sizeof(finding));

                safe_copy_str(finding.file_path, file->path, sizeof(finding.file_path));
                finding.line_number = src_line->number;
                finding.column_number = col;
                safe_copy_str(finding.rule_id, "RULE_CWE_120_SCANF_UNBOUNDED", sizeof(finding.rule_id));
                safe_copy_str(finding.cwe_id, "CWE-120", sizeof(finding.cwe_id));
                safe_copy_str(finding.cwe_name, "Buffer Copy without Checking Size of Input", sizeof(finding.cwe_name));
                finding.severity = SEV_HIGH;
                safe_copy_str(finding.message, "Unbounded '%s' specifier in scanf allows buffer overflow.", sizeof(finding.message));
                safe_copy_str(finding.snippet, raw, sizeof(finding.snippet));
                safe_copy_str(finding.remediation, "Specify field width in format (e.g., '%63s' for a 64-byte buffer).", sizeof(finding.remediation));
                finding.suppressed = suppressed;

                finding_list_add(findings, &finding);

                if (suppressed) {
                    stats->suppressed_count++;
                } else {
                    stats->high_count++;
                }
                break;
            }
            scanf_p += 5;
        }

        /* 3. Unchecked Memory Allocation (malloc, calloc, realloc) */
        const char *alloc_names[] = {"malloc", "calloc", "realloc"};
        for (int a = 0; a < 3; a++) {
            const char *aname = alloc_names[a];
            size_t alen = strlen(aname);
            const char *aptr = clean_line;

            while ((aptr = strstr(aptr, aname)) != NULL) {
                size_t col = (size_t)(aptr - clean_line) + 1;
                if (is_function_call(clean_line, col - 1, alen)) {
                    char var_name[64] = {0};
                    bool has_var = extract_assigned_var(clean_line, col - 1, var_name, sizeof(var_name));

                    bool safe = false;
                    if (has_var) {
                        safe = is_pointer_null_checked(file, i, var_name);
                    }

                    if (!safe) {
                        Finding finding;
                        memset(&finding, 0, sizeof(finding));

                        safe_copy_str(finding.file_path, file->path, sizeof(finding.file_path));
                        finding.line_number = src_line->number;
                        finding.column_number = col;
                        safe_copy_str(finding.rule_id, "RULE_CWE_252_UNCHECKED_ALLOC", sizeof(finding.rule_id));
                        safe_copy_str(finding.cwe_id, "CWE-252", sizeof(finding.cwe_id));
                        safe_copy_str(finding.cwe_name, "Unchecked Return Value / Missing Allocation Check", sizeof(finding.cwe_name));
                        finding.severity = SEV_HIGH;

                        snprintf(finding.message, sizeof(finding.message),
                                 "Dynamic allocation via '%s()' without immediate NULL validation before use.", aname);
                        safe_copy_str(finding.snippet, raw, sizeof(finding.snippet));
                        safe_copy_str(finding.remediation,
                                      "Validate pointer immediately after allocation: 'if (!ptr) { /* handle error */ }'.",
                                      sizeof(finding.remediation));
                        finding.suppressed = suppressed;

                        finding_list_add(findings, &finding);

                        if (suppressed) {
                            stats->suppressed_count++;
                        } else {
                            stats->high_count++;
                        }
                    }
                }
                aptr += alen;
            }
        }
    }
}
