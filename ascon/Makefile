BUILD_DIR := build

CC       := gcc
CFLAGS   := -march=native -O3 -DOUTPUT_DIR=\"$(BUILD_DIR)\"
# CFLAGS   += -DASCON_PRINT_STATE

TEST_SRCS  := tests/genkat_hash.c
INCLUDES   := -Itests

ASCON_SRCS := $(wildcard xof128/*.c)
INCLUDES   += -Ixof128
# ASCON_SRCS := $(wildcard hash256/*.c)
# INCLUDES   += -Ihash256

SRCS := $(ASCON_SRCS) $(TEST_SRCS)
TARGET := $(BUILD_DIR)/genkat

all: $(TARGET)
	$^

$(TARGET): $(SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
