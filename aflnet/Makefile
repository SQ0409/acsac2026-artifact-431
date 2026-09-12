CC ?= gcc

# Minimal Linux build. The compatibility headers provide the small DOT graph
# API and optional libcap types used by afl-fuzz. OpenSSL is used by the
# NGAP/NAS security helpers.
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-pointer-sign -Wno-unused-result
CFLAGS += -I../compat -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
          -DBIN_PATH=\".\" -DDOC_PATH=\".\"
LDFLAGS ?=
LDLIBS ?= -ldl -lm -lssl -lcrypto

OBJS = afl-fuzz.o aflnet.o hmac-sha256.o sha256.o

.PHONY: all clean

all: afl-fuzz

afl-fuzz: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f afl-fuzz $(OBJS)
