CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -Iinclude
LIBS    = -lsqlite3 -lcrypto
TARGET  = pwmgr
SRCDIR  = src
OBJDIR  = build
BINDIR  ?= $(HOME)/.local/bin
SRCS    = $(SRCDIR)/main.c \
          $(SRCDIR)/cmd_init.c \
          $(SRCDIR)/cmd_add.c \
          $(SRCDIR)/cmd_get.c \
          $(SRCDIR)/cmd_delete.c \
          $(SRCDIR)/cmd_list.c \
          $(SRCDIR)/cmd_generate.c \
          $(SRCDIR)/cmd_change_master.c \
          $(SRCDIR)/cmd_migrate.c \
          $(SRCDIR)/cmd_private.c \
          $(SRCDIR)/auth.c \
          $(SRCDIR)/db.c \
          $(SRCDIR)/crypto_utils.c
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
TEST_BINS = $(OBJDIR)/test_hash $(OBJDIR)/test_crypto_utils
TEST_SCRIPTS = tests/test_cli_basic.sh tests/test_cli_migrate.sh tests/test_cli_generate.sh

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

test: $(TARGET) $(TEST_BINS)
	./$(OBJDIR)/test_hash
	./$(OBJDIR)/test_crypto_utils
	./tests/test_cli_basic.sh
	./tests/test_cli_migrate.sh

$(OBJDIR)/test_hash: tests/test_hash.c | $(OBJDIR)
	$(CC) $(CFLAGS) $< -lcrypto -o $@

$(OBJDIR)/test_crypto_utils: tests/test_crypto_utils.c src/crypto_utils.c | $(OBJDIR)
	$(CC) $(CFLAGS) $^ -lcrypto -o $@

install: $(TARGET)
	mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)/$(TARGET)

uninstall:
	rm -f $(BINDIR)/$(TARGET)

.PHONY: all clean test install uninstall
