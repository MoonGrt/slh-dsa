OBJDIR := build

# SRC
CSRC   := $(wildcard slh/*.c) $(wildcard hash/*.c)
# OBJ
OBJS   := $(patsubst %.c,$(OBJDIR)/%.o,$(CSRC))
DIRS   := $(sort $(dir $(OBJS)))
# TARGET
XTEST     := $(OBJDIR)/test
XTESTC    := test/test.c
XFIPS205  := $(OBJDIR)/xfips205
XFIPS205C := test/xfips205.c

CC     ?= gcc
CFLAGS := -Wall -Wextra -Werror=unused-result -Wpedantic -Werror \
          -Wmissing-prototypes -Wshadow -Wpointer-arith \
          -Wredundant-decls -Wno-long-long -Wno-unknown-pragmas \
          -O3 -std=c99 -fomit-frame-pointer -pedantic \
          -Ihash -Islh \
          $(CFLAGS)
LDLIBS +=

default: $(XFIPS205)
.PHONY: default

$(DIRS):
	@mkdir -p $@

$(XTEST): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

$(XFIPS205): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XFIPS205C) $(LDLIBS)

$(OBJDIR)/%.o: %.c | $(DIRS)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(XTEST)
	@echo -e "-------------------- test --------------------"
	./test/acvp_case.sh
.PHONY: test

test-all: $(XFIPS205)
	@echo -e "-------------------- test --------------------"
	python3 test/acvp_client.py
.PHONY: test-all

clean:
	$(RM) -rf $(OBJDIR) *.rsp *.req *.log
.PHONY: clean

clean-all:
	cd test && $(MAKE) clean
.PHONY: clean-all
