/**
 * @file vulnerable_sample.c
 * @brief Deliberately vulnerable C sample demonstrating high-risk CWE security flaws
 *        for static analysis validation.
 * @warning FOR TESTING AND SAST VALIDATION PURPOSES ONLY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger_cwe_242_gets(void) {
    char user_buffer[64];
    printf("Enter input: ");
    /* Flaw 1: gets() inherently dangerous (CWE-242) */
    gets(user_buffer);
    printf("Read: %s\n", user_buffer);
}

void trigger_cwe_120_strcpy_strcat(const char *untrusted_input) {
    char dest[32];
    /* Flaw 2: strcpy() without bounds check (CWE-120) */
    strcpy(dest, untrusted_input);

    char suffix[16] = "_authenticated";
    /* Flaw 3: strcat() without bounds check (CWE-120) */
    strcat(dest, suffix);
    printf("Destination: %s\n", dest);
}

void trigger_cwe_120_sprintf(const char *user_id) {
    char query[128];
    /* Flaw 4: sprintf() without length limits (CWE-120) */
    sprintf(query, "SELECT * FROM accounts WHERE uid='%s'", user_id);
    printf("Executed query: %s\n", query);
}

void trigger_cwe_78_system(const char *filename) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", filename);
    /* Flaw 5: system() shell command execution (CWE-78) */
    system(cmd);
}

void trigger_cwe_120_scanf(void) {
    char username[32];
    printf("Username: ");
    /* Flaw 6: scanf unbounded string reading (CWE-120) */
    scanf("%s", username);
    printf("User: %s\n", username);
}

void trigger_cwe_252_unchecked_malloc(size_t len) {
    /* Flaw 7: malloc without NULL check (CWE-252 / CWE-401) */
    char *buffer = (char *)malloc(len);
    strcpy(buffer, "Pre-allocated string content");
    printf("Buffer: %s\n", buffer);
    free(buffer);
}

void trigger_cwe_252_unchecked_calloc(size_t count) {
    /* Flaw 8: calloc without NULL check (CWE-252 / CWE-401) */
    int *numbers = (int *)calloc(count, sizeof(int));
    numbers[0] = 42;
    printf("First number: %d\n", numbers[0]);
    free(numbers);
}

int main(int argc, char *argv[]) {
    printf("=== Vulnerability Test Suite Running ===\n");
    if (argc > 1) {
        trigger_cwe_120_strcpy_strcat(argv[1]);
        trigger_cwe_120_sprintf(argv[1]);
        trigger_cwe_78_system(argv[1]);
    }
    return 0;
}
