OBJDIR := build

# SRC
CSRC   := $(wildcard slh/*.c) $(wildcard hash/*.c)
# OBJ
OBJS   := $(patsubst %.c,$(OBJDIR)/%.o,$(CSRC))
DIRS   := $(sort $(dir $(OBJS)))
# TARGET
XTEST     := $(OBJDIR)/test
XTESTC    := test/test.c
XASCON    := $(OBJDIR)/ascon_kat
XASCONC   := test/ascon_kat.c
XFIPS205  := $(OBJDIR)/xfips205
XFIPS205C := test/xfips205.c

CC     ?= gcc
CFLAGS := -Wall -Wextra -Werror=unused-result -Wpedantic -Werror \
          -Wmissing-prototypes -Wshadow -Wpointer-arith \
          -Wredundant-decls -Wno-long-long -Wno-unknown-pragmas \
          -std=c99 -fomit-frame-pointer -pedantic \
          -Ihash -Islh \
          $(CFLAGS)
CFLAGS += -g -O0
# CFLAGS += -O3
LDLIBS +=

default: $(XFIPS205)
.PHONY: default

$(DIRS):
	@mkdir -p $@

$(XTEST): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

$(XASCON): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XASCONC) $(LDLIBS)

$(XFIPS205): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XFIPS205C) $(LDLIBS)

$(OBJDIR)/%.o: %.c | $(DIRS)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(XTEST)
	@echo -e "-------------------- test --------------------"
	./test/test
.PHONY: test

test-ascon: $(XASCON)
	@echo -e "-------------------- test --------------------"
	./test/ascon_kat
.PHONY: test

test-all: $(XFIPS205)
	@echo -e "-------------------- test --------------------"
	python3 test/acvp_client.py
.PHONY: test-all

gdb: $(XTEST)
	gdb ./$(XTEST)
.PHONY: gdb

clean:
	$(RM) -rf $(OBJDIR) *.rsp *.req *.log
.PHONY: clean

clean-all:
	cd test && $(MAKE) clean
.PHONY: clean-all
