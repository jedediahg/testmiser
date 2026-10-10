CC ?= cc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
LDFLAGS ?=
LDLIBS ?= -lcrypto

BUILD_DIR := build
TARGET := $(BUILD_DIR)/tm
SOURCES := src/main.c src/backend.c src/observer.c src/observer_report.c src/observed_inputs.c src/digest.c src/attestation.c src/identity.c src/context.c src/input.c src/verification.c src/json.c src/result.c src/outputs.c src/trust.c src/validate.c src/profile.c src/repo.c src/clean.c src/lock.c src/local_store.c src/runtime.c
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all test clean

all: $(TARGET)

test: $(TARGET) $(BUILD_DIR)/openat2_probe $(BUILD_DIR)/open_mode_probe $(BUILD_DIR)/descriptor_dup_probe $(BUILD_DIR)/clone3_probe $(BUILD_DIR)/cwd_probe $(BUILD_DIR)/path_error_probe $(BUILD_DIR)/network_syscall_probe $(BUILD_DIR)/test_digest $(BUILD_DIR)/test_attestation $(BUILD_DIR)/test_identity $(BUILD_DIR)/test_context $(BUILD_DIR)/test_input $(BUILD_DIR)/test_verification $(BUILD_DIR)/test_json $(BUILD_DIR)/test_result $(BUILD_DIR)/test_outputs $(BUILD_DIR)/test_trust $(BUILD_DIR)/test_profile $(BUILD_DIR)/test_repo $(BUILD_DIR)/test_lock $(BUILD_DIR)/test_local_store $(BUILD_DIR)/test_runtime $(BUILD_DIR)/test_backend $(BUILD_DIR)/test_observer_report $(BUILD_DIR)/test_observed_inputs
	TM_BIN=./$(TARGET) OPENAT2_PROBE=./$(BUILD_DIR)/openat2_probe OPEN_MODE_PROBE=./$(BUILD_DIR)/open_mode_probe DESCRIPTOR_DUP_PROBE=./$(BUILD_DIR)/descriptor_dup_probe CLONE3_PROBE=./$(BUILD_DIR)/clone3_probe CWD_PROBE=./$(BUILD_DIR)/cwd_probe PATH_ERROR_PROBE=./$(BUILD_DIR)/path_error_probe sh tests/cli.sh
	./$(BUILD_DIR)/test_digest
	./$(BUILD_DIR)/test_attestation
	./$(BUILD_DIR)/test_identity
	./$(BUILD_DIR)/test_context
	./$(BUILD_DIR)/test_input
	./$(BUILD_DIR)/test_verification
	./$(BUILD_DIR)/test_json
	./$(BUILD_DIR)/test_result
	./$(BUILD_DIR)/test_outputs
	./$(BUILD_DIR)/test_trust
	./$(BUILD_DIR)/test_profile
	./$(BUILD_DIR)/test_repo
	./$(BUILD_DIR)/test_lock
	./$(BUILD_DIR)/test_local_store
	./$(BUILD_DIR)/test_runtime
	./$(BUILD_DIR)/test_backend
	./$(BUILD_DIR)/test_observer_report
	./$(BUILD_DIR)/test_observed_inputs

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/openat2_probe: tests/openat2_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/open_mode_probe: tests/open_mode_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/descriptor_dup_probe: tests/descriptor_dup_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/clone3_probe: tests/clone3_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/cwd_probe: tests/cwd_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/path_error_probe: tests/path_error_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/network_syscall_probe: tests/network_syscall_probe.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/test_digest: tests/digest.c src/digest.c include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/digest.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_attestation: tests/attestation.c src/attestation.c src/digest.c include/tm/attestation.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/attestation.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_identity: tests/identity.c src/identity.c src/digest.c include/tm/identity.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/identity.c src/identity.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_context: tests/context.c src/context.c src/json.c src/digest.c include/tm/context.h include/tm/json.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/context.c src/context.c src/json.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_input: tests/input.c src/input.c src/json.c src/digest.c include/tm/input.h include/tm/json.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/input.c src/input.c src/json.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_verification: tests/verification.c src/verification.c src/digest.c include/tm/verification.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/verification.c src/verification.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_json: tests/json.c src/json.c include/tm/json.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/json.c src/json.c $(LDLIBS)

$(BUILD_DIR)/test_result: tests/result.c src/result.c src/outputs.c src/input.c src/identity.c src/trust.c src/json.c src/verification.c src/attestation.c src/digest.c include/tm/result.h include/tm/outputs.h include/tm/input.h include/tm/identity.h include/tm/trust.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/result.c src/result.c src/outputs.c src/input.c src/identity.c src/trust.c src/json.c src/verification.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_outputs: tests/outputs.c src/outputs.c include/tm/outputs.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/outputs.c src/outputs.c $(LDLIBS)

$(BUILD_DIR)/test_trust: tests/trust.c src/trust.c src/json.c src/attestation.c src/digest.c include/tm/trust.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/trust.c src/trust.c src/json.c src/attestation.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_profile: tests/profile.c src/profile.c src/json.c src/digest.c include/tm/profile.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/profile.c src/profile.c src/json.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_repo: tests/repo.c src/repo.c include/tm/repo.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/repo.c src/repo.c

$(BUILD_DIR)/test_lock: tests/lock.c src/lock.c src/local_store.c src/digest.c include/tm/lock.h include/tm/local_store.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/lock.c src/lock.c src/local_store.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_local_store: tests/local_store.c src/local_store.c include/tm/local_store.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/local_store.c src/local_store.c

$(BUILD_DIR)/test_runtime: tests/runtime.c src/runtime.c src/digest.c include/tm/runtime.h include/tm/digest.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/runtime.c src/runtime.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_backend: tests/backend.c tests/fake-bwrap.sh src/backend.c src/profile.c src/repo.c src/json.c src/digest.c include/tm/backend.h include/tm/profile.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -DTM_TEST_BWRAP='"tests/fake-bwrap.sh"' -o $@ tests/backend.c src/backend.c src/profile.c src/repo.c src/json.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/test_observer_report: tests/observer_report.c src/observer_report.c include/tm/observer.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/observer_report.c src/observer_report.c

$(BUILD_DIR)/test_observed_inputs: tests/observed_inputs.c src/observed_inputs.c src/observer_report.c src/input.c src/json.c src/digest.c include/tm/observed_inputs.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/observed_inputs.c src/observed_inputs.c src/observer_report.c src/input.c src/json.c src/digest.c $(LDLIBS)

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
