PARAMS ?= sphincs-haraka-128f
THASH  ?= robust
TEST   ?= PQCgenKAT
TRACE  ?= 1

CC        = gcc
SLH_DIR   = slh
HASH_DIR  = hash
TEST_DIR  = test
PARAM_DIR = params
BUILD_DIR = build
CFLAGS    = -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes \
            -DPARAMS=$(PARAMS) -I$(SLH_DIR) -I$(PARAM_DIR) -I$(HASH_DIR) -I$(TEST_DIR)

SOURCES = slh/address.c slh/randombytes.c slh/merkle.c slh/wots.c slh/wotsx1.c slh/utils.c slh/fors.c slh/sign.c test/cycles.c
HEADERS = slh/params.h slh/address.h slh/randombytes.h slh/merkle.h slh/wots.h slh/wotsx1.h slh/utils.h slh/fors.h slh/api.h

ifeq ($(TRACE),1)
    CFLAGS  += -DENABLE_TRACE
    SOURCES += slh/trace.c
    HEADERS += slh/trace.h
endif

HEADERS += hash/hash.h hash/thash.h
ifneq (,$(findstring shake,$(PARAMS)))
    SOURCES += hash/fips202.c hash/hash_shake.c hash/thash_shake_$(THASH).c
    HEADERS += hash/fips202.h hash/shake_offsets.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
    SOURCES += hash/haraka.c hash/hash_haraka.c hash/thash_haraka_$(THASH).c
    HEADERS += hash/haraka.h hash/haraka_offsets.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
    SOURCES += hash/sha2.c hash/hash_sha2.c hash/thash_sha2_$(THASH).c
    HEADERS += hash/sha2.h hash/sha2_offsets.h
endif

DET_SOURCES = $(SOURCES:slh/randombytes.%=slh/rng.%)
DET_HEADERS = $(HEADERS:slh/randombytes.%=slh/rng.%)

TEST_SRC = $(TEST_DIR)/$(TEST).c
TEST_BIN = $(BUILD_DIR)/$(TEST)

default: run

all: $(TEST_BIN)
.PHONY: all

run: $(TEST_BIN)
	@$(TEST_BIN)
.PHONY: all

$(TEST_BIN): $(TEST_SRC) $(DET_SOURCES) $(DET_HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

clean:
	-$(RM) -r $(BUILD_DIR)
	-$(RM) *.rsp *.req *.json
