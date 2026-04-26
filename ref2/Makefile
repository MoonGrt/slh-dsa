XBIN    ?= kat_test
KATNUM  ?= 1

BUILD   := build

SLH_DIR := slh
HASH_DIR:= hash

CSRC    := $(wildcard $(SLH_DIR)/*.c) $(wildcard $(HASH_DIR)/*.c)
TARGET  := $(BUILD)/$(XBIN)

CC      := gcc
CFLAGS  += -Wall -march=native -Ofast -DNDEBUG
CFLAGS  += -I. -I$(SLH_DIR) -I$(HASH_DIR) -DKATNUM=$(KATNUM)

LDLIBS  +=

all: test

$(BUILD):
	mkdir -p $(BUILD)

$(TARGET): $(CSRC) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(CSRC) $(LDLIBS)

test: $(TARGET)
	$^
	sha256sum *.rsp > $(BUILD)/t.log
	cat $(BUILD)/t.log ../kat/kat$(KATNUM)-sha256.txt | sort | uniq -c -w 64
	@echo "NOTE >2<- indicates test vector comparison match, 1 is a failure."

clean:
	$(RM) -rf $(BUILD) *.rsp *.req
