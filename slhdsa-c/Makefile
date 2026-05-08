.PHONY: default test clean

OBJDIR := build

# SRC
CSRC   := $(wildcard slh/*.c) $(wildcard hash/*.c)
# OBJ
OBJS   := $(patsubst %.c,$(OBJDIR)/%.o,$(CSRC))
DIRS   := $(sort $(dir $(OBJS)))
# TARGET
XTEST  ?= xfips205
XTESTC ?= test/xfips205.c
TARGET := $(OBJDIR)/$(XTEST)

CC     ?= gcc
CFLAGS := -Wall -Wextra -Werror=unused-result -Wpedantic -Werror \
          -Wmissing-prototypes -Wshadow -Wpointer-arith \
          -Wredundant-decls -Wno-long-long -Wno-unknown-pragmas \
          -O3 -std=c99 -fomit-frame-pointer -pedantic \
          -Ihash -Islh \
          $(CFLAGS)

LDLIBS +=

default: $(TARGET)

$(DIRS):
	@mkdir -p $@

$(TARGET): $(OBJS) | $(DIRS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XTESTC) $(LDLIBS)

$(OBJDIR)/%.o: %.c | $(DIRS)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	python3 test/acvp_client.py

clean:
	$(RM) -rf $(OBJDIR) *.rsp *.req *.log
	cd test && $(MAKE) clean
