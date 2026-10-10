CC ?= cc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
LDFLAGS ?=
LDLIBS ?= -lcrypto

BUILD_DIR := build
TARGET := $(BUILD_DIR)/tm
SOURCES := src/main.c src/observer.c src/digest.c src/attestation.c
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all test clean

all: $(TARGET)

test: $(TARGET) $(BUILD_DIR)/test_digest $(BUILD_DIR)/test_attestation
	TM_BIN=./$(TARGET) sh tests/cli.sh
	./$(BUILD_DIR)/test_digest
	./$(BUILD_DIR)/test_attestation

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/test_digest: tests/digest.c src/digest.c include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/digest.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_attestation: tests/attestation.c src/attestation.c src/digest.c include/tm/attestation.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/attestation.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
