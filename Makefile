CC     = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11
LIBS   = -lsqlite3
TARGET = pwmgr
SRCS   = main.c db.c auth.c commands.c
OBJS   = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
