CC ?= cc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
LDFLAGS ?=
LDLIBS ?= -lcrypto

BUILD_DIR := build
TARGET := $(BUILD_DIR)/tm
SOURCES := src/main.c src/observer.c src/digest.c src/attestation.c src/identity.c src/verification.c src/json.c src/result.c src/trust.c src/validate.c
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all test clean

all: $(TARGET)

test: $(TARGET) $(BUILD_DIR)/test_digest $(BUILD_DIR)/test_attestation $(BUILD_DIR)/test_identity $(BUILD_DIR)/test_verification $(BUILD_DIR)/test_json $(BUILD_DIR)/test_result $(BUILD_DIR)/test_trust
	TM_BIN=./$(TARGET) sh tests/cli.sh
	./$(BUILD_DIR)/test_digest
	./$(BUILD_DIR)/test_attestation
	./$(BUILD_DIR)/test_identity
	./$(BUILD_DIR)/test_verification
	./$(BUILD_DIR)/test_json
	./$(BUILD_DIR)/test_result
	./$(BUILD_DIR)/test_trust

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/test_digest: tests/digest.c src/digest.c include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/digest.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_attestation: tests/attestation.c src/attestation.c src/digest.c include/tm/attestation.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/attestation.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_identity: tests/identity.c src/identity.c src/digest.c include/tm/identity.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/identity.c src/identity.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_verification: tests/verification.c src/verification.c src/digest.c include/tm/verification.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/verification.c src/verification.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_json: tests/json.c src/json.c include/tm/json.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/json.c src/json.c $(LDLIBS)

$(BUILD_DIR)/test_result: tests/result.c src/result.c src/trust.c src/json.c src/verification.c src/attestation.c src/digest.c include/tm/result.h include/tm/trust.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/result.c src/result.c src/trust.c src/json.c src/verification.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_trust: tests/trust.c src/trust.c src/json.c src/attestation.c src/digest.c include/tm/trust.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/trust.c src/trust.c src/json.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
