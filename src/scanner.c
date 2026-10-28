/**
 * @file scanner.c
 * @brief Source code ingestion, line tokenization, suppression tag verification,
 *        and recursive directory scanning implementation.
 * @project c-security-auditor
 */

#include "scanner.h"
#include "rules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define INITIAL_LINE_CAPACITY 128
#define INITIAL_FINDINGS_CAPACITY 32

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
 * @brief Case-insensitive substring search helper.
 */
static const char *str_case_str(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return haystack;

    size_t needle_len = strlen(needle);
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            size_t i;
            for (i = 1; i < needle_len; i++) {
                if (!haystack[i] || tolower((unsigned char)haystack[i]) != tolower((unsigned char)needle[i])) {
                    break;
                }
            }
            if (i == needle_len) {
                return haystack;
            }
        }
    }
    return NULL;
}

/**
 * @brief Checks if a line contains the suppression marker "// sast-ignore".
 */
bool is_line_suppressed(const char *line) {
    if (!line) return false;

    /* Check for // sast-ignore */
    const char *line_comment = strstr(line, "//");
    if (line_comment) {
        if (str_case_str(line_comment, "sast-ignore") != NULL) {
            return true;
        }
    }

    /* Check for block comment pattern "sast-ignore" */
    const char *block_comment = strstr(line, "/*");
    if (block_comment) {
        if (str_case_str(block_comment, "sast-ignore") != NULL) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Loads a source code file into memory line-by-line.
 */
SourceFile *source_file_load(const char *path) {
    if (!path) return NULL;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }

    SourceFile *sf = (SourceFile *)malloc(sizeof(SourceFile));
    if (!sf) {
        fclose(fp);
        return NULL;
    }

    safe_copy_str(sf->path, path, sizeof(sf->path));

    sf->line_count = 0;
    sf->capacity = INITIAL_LINE_CAPACITY;
    sf->lines = (SourceLine *)malloc(sf->capacity * sizeof(SourceLine));
    if (!sf->lines) {
        free(sf);
        fclose(fp);
        return NULL;
    }

    char buffer[MAX_LINE_BUFFER];
    size_t current_line_num = 1;

    while (fgets(buffer, sizeof(buffer), fp)) {
        /* Strip trailing carriage return and newline */
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\r' || buffer[len - 1] == '\n')) {
            buffer[--len] = '\0';
        }

        if (sf->line_count >= sf->capacity) {
            size_t new_cap = sf->capacity * 2;
            SourceLine *new_lines = (SourceLine *)realloc(sf->lines, new_cap * sizeof(SourceLine));
            if (!new_lines) {
                /* Out of memory */
                source_file_free(sf);
                fclose(fp);
                return NULL;
            }
            sf->lines = new_lines;
            sf->capacity = new_cap;
        }

        char *line_copy = (char *)malloc(len + 1);
        if (!line_copy) {
            source_file_free(sf);
            fclose(fp);
            return NULL;
        }
        memcpy(line_copy, buffer, len + 1);

        sf->lines[sf->line_count].number = current_line_num++;
        sf->lines[sf->line_count].content = line_copy;
        sf->lines[sf->line_count].has_suppression = is_line_suppressed(line_copy);
        sf->line_count++;
    }

    fclose(fp);
    return sf;
}

/**
 * @brief Frees all memory allocated for a SourceFile.
 */
void source_file_free(SourceFile *sf) {
    if (!sf) return;

    if (sf->lines) {
        for (size_t i = 0; i < sf->line_count; i++) {
            free(sf->lines[i].content);
        }
        free(sf->lines);
    }
    free(sf);
}

/**
 * @brief Allocates and initializes an empty FindingList.
 */
FindingList *finding_list_create(void) {
    FindingList *list = (FindingList *)malloc(sizeof(FindingList));
    if (!list) return NULL;

    list->count = 0;
    list->capacity = INITIAL_FINDINGS_CAPACITY;
    list->items = (Finding *)malloc(list->capacity * sizeof(Finding));
    if (!list->items) {
        free(list);
        return NULL;
    }
    return list;
}

/**
 * @brief Appends a finding to the dynamic FindingList.
 */
void finding_list_add(FindingList *list, const Finding *finding) {
    if (!list || !finding) return;

    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity * 2;
        Finding *new_items = (Finding *)realloc(list->items, new_cap * sizeof(Finding));
        if (!new_items) return;
        list->items = new_items;
        list->capacity = new_cap;
    }

    list->items[list->count] = *finding;
    list->count++;
}

/**
 * @brief Deallocates all resources held by a FindingList.
 */
void finding_list_free(FindingList *list) {
    if (!list) return;
    free(list->items);
    free(list);
}

/**
 * @brief Scans an individual source file and adds findings.
 */
int scan_file(const char *file_path, FindingList *findings, ScanStats *stats) {
    if (!file_path || !findings || !stats) return -1;

    SourceFile *sf = source_file_load(file_path);
    if (!sf) {
        return -1;
    }

    stats->files_scanned++;
    stats->lines_scanned += sf->line_count;

    rules_analyze_file(sf, findings, stats);

    source_file_free(sf);
    return 0;
}

/**
 * @brief Checks if a given filename matches C/C++ source code extensions.
 */
static bool is_c_source_file(const char *filename) {
    if (!filename) return false;
    const char *dot = strrchr(filename, '.');
    if (!dot) return false;

    return (strcmp(dot, ".c") == 0 ||
            strcmp(dot, ".h") == 0 ||
            strcmp(dot, ".cpp") == 0 ||
            strcmp(dot, ".hpp") == 0 ||
            strcmp(dot, ".cc") == 0 ||
            strcmp(dot, ".cxx") == 0);
}

/**
 * @brief Recursively traverses a directory, scanning all matching C source files.
 */
int scan_directory(const char *dir_path, FindingList *findings, ScanStats *stats) {
    if (!dir_path || !findings || !stats) return -1;

    DIR *dir = opendir(dir_path);
    if (!dir) {
        return -1;
    }

    struct dirent *entry;
    char path_buf[MAX_PATH_LEN];

    while ((entry = readdir(dir)) != NULL) {
        /* Ignore '.' and '..' */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Ignore hidden folders (.git, etc.) and build directory */
        if (entry->d_name[0] == '.' ||
            strcmp(entry->d_name, "build") == 0 ||
            strcmp(entry->d_name, "node_modules") == 0) {
            continue;
        }

        /* Build full path */
        size_t len = strlen(dir_path);
        if (len > 0 && (dir_path[len - 1] == '/' || dir_path[len - 1] == '\\')) {
            snprintf(path_buf, sizeof(path_buf), "%s%s", dir_path, entry->d_name);
        } else {
            snprintf(path_buf, sizeof(path_buf), "%s/%s", dir_path, entry->d_name);
        }

        struct stat st;
        if (stat(path_buf, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            scan_directory(path_buf, findings, stats);
        } else if (S_ISREG(st.st_mode)) {
            if (is_c_source_file(entry->d_name)) {
                scan_file(path_buf, findings, stats);
            }
        }
    }

    closedir(dir);
    return 0;
}

/**
 * @brief Dispatch entry point to scan either a single file or an entire directory tree.
 */
int scan_path(const char *target_path, FindingList *findings, ScanStats *stats) {
    if (!target_path || !findings || !stats) return -1;

    struct stat st;
    if (stat(target_path, &st) != 0) {
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        return scan_directory(target_path, findings, stats);
    } else if (S_ISREG(st.st_mode)) {
        return scan_file(target_path, findings, stats);
    }

    return -1;
}
