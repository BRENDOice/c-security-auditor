# ==============================================================================
# Makefile for c-security-auditor (SAST DevSecOps Static Analysis Tool)
# Standards: C11 (ISO/IEC 9899:2011) with Strict Compiler Constraints
# ==============================================================================

CC ?= gcc
STD_FLAGS = -std=c11
WARN_FLAGS = -Wall -Wextra -Werror -pedantic -Wformat=2 -Wshadow -Wwrite-strings
OPT_FLAGS ?= -O2

CFLAGS ?= $(STD_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS)
CPPFLAGS = -Iinclude

SRC_DIR = src
INC_DIR = include
TESTS_DIR = tests
BUILD_DIR = build

SRCS = $(SRC_DIR)/scanner.c \
       $(SRC_DIR)/rules.c \
       $(SRC_DIR)/report.c \
       $(SRC_DIR)/main.c

OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

ifeq ($(OS),Windows_NT)
    TARGET = $(BUILD_DIR)/c-security-auditor.exe
    RM = del /Q /F
    MKDIR = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
else
    TARGET = $(BUILD_DIR)/c-security-auditor
    RM = rm -rf
    MKDIR = mkdir -p $(BUILD_DIR)
endif

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all clean test install help

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	@echo "Linking binary: $@"
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Build successful: $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling C source: $<"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@$(MKDIR)

test: $(TARGET)
	@echo "=================================================="
	@echo "Running Automated SAST Security Test Suite"
	@echo "=================================================="
	@echo "\n[1/3] Testing Vulnerability Detection Engine..."
	-@$(TARGET) $(TESTS_DIR)/vulnerable_sample.c -o $(BUILD_DIR)/report.md -f markdown || true
	@echo "\n[2/3] Testing JSON Serialization..."
	-@$(TARGET) $(TESTS_DIR)/vulnerable_sample.c -o $(BUILD_DIR)/report.json -f json || true
	@echo "\n[3/3] Testing Clean Code & Suppression (// sast-ignore)..."
	@$(TARGET) $(TESTS_DIR)/clean_sample.c
	@echo "\n[+] All SAST test suites executed successfully."

clean:
	@echo "Cleaning build artifacts..."
ifeq ($(OS),Windows_NT)
	-@$(RM) $(BUILD_DIR)\*.o $(TARGET) $(BUILD_DIR)\*.md $(BUILD_DIR)\*.json 2>nul || true
else
	@$(RM) $(BUILD_DIR)
endif
	@echo "Clean completed."

install: $(TARGET)
	@echo "Installing $(TARGET) to $(DESTDIR)$(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)
	@echo "Installation finished."

help:
	@echo "c-security-auditor Makefile Targets:"
	@echo "  all     - Compile and link c-security-auditor executable (default)"
	@echo "  test    - Build and execute SAST test suite on sample sources"
	@echo "  clean   - Remove all generated object files and binaries"
	@echo "  install - Install executable to system bin directory"
	@echo "  help    - Display this target guide"
