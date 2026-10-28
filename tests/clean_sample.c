/**
 * @file clean_sample.c
 * @brief Secure C code sample demonstrating remediated patterns and deliberate
 *        inline suppression using "// sast-ignore".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int safe_input_handling(void) {
    char user_buffer[64];
    printf("Enter input: ");
    /* Remediated CWE-242: bounded input via fgets */
    if (fgets(user_buffer, sizeof(user_buffer), stdin) == NULL) {
        return -1;
    }

    /* Remediated CWE-120: scanf with strict 31-char width limit */
    char username[32];
    printf("Username: ");
    if (scanf("%31s", username) != 1) {
        return -1;
    }

    return 0;
}

int safe_string_manipulation(const char *untrusted_input) {
    char dest[64];
    /* Remediated CWE-120: snprintf enforces destination buffer limits */
    snprintf(dest, sizeof(dest), "%s", untrusted_input);

    char suffix[16] = "_authenticated";
    /* Bounded concatenation using snprintf */
    char combined[128];
    snprintf(combined, sizeof(combined), "%s%s", dest, suffix);

    printf("Safe output: %s\n", combined);
    return 0;
}

int safe_memory_management(size_t size) {
    if (size == 0) return -1;

    /* Remediated CWE-252: explicit NULL check immediately following allocation */
    char *buffer = (char *)malloc(size);
    if (!buffer) {
        perror("Memory allocation failed");
        return -1;
    }

    memset(buffer, 0, size);
    buffer[0] = 'S';
    printf("Safe buffer initialized: %c\n", buffer[0]);

    free(buffer);
    return 0;
}

void legacy_adapter_suppressed(void) {
    char fixed_buffer[32];

    /* Intentionally suppressed legacy pattern reviewed and approved by security lead */
    strcpy(fixed_buffer, "known_static_literal"); // sast-ignore

    printf("Legacy adapter: %s\n", fixed_buffer);
}

int main(void) {
    printf("=== Clean Sample Executing Safely ===\n");
    safe_memory_management(256);
    legacy_adapter_suppressed();
    return 0;
}
